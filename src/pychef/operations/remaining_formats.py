"""Dependency-free structured formats, media metadata, and file carving operations."""

from __future__ import annotations

import base64
import json
import re
import struct
import zlib
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def take(self, length: int) -> bytes:
        value = self.data[self.position : self.position + length]
        if len(value) != length:
            raise ValueError("Unexpected end of input")
        self.position += length
        return value

    def byte(self) -> int:
        return self.take(1)[0]


def _json_input(value: Data) -> Any:
    return json.loads(to_text(value))


def _json_output(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _amf0_decode(reader: _Reader) -> Any:
    marker = reader.byte()
    if marker == 0:
        return struct.unpack(">d", reader.take(8))[0]
    if marker == 1:
        return bool(reader.byte())
    if marker in {2, 12}:
        length = int.from_bytes(reader.take(2 if marker == 2 else 4), "big")
        return reader.take(length).decode("utf-8", "replace")
    if marker in {3, 8}:
        if marker == 8:
            reader.take(4)
        result: dict[str, Any] = {}
        while True:
            length = int.from_bytes(reader.take(2), "big")
            if length == 0 and reader.data[reader.position : reader.position + 1] == b"\x09":
                reader.position += 1
                return result
            name = reader.take(length).decode("utf-8", "replace")
            result[name] = _amf0_decode(reader)
    if marker in {5, 6}:
        return None
    if marker == 10:
        return [_amf0_decode(reader) for _ in range(int.from_bytes(reader.take(4), "big"))]
    if marker == 11:
        timestamp = struct.unpack(">d", reader.take(8))[0]
        reader.take(2)
        return {"$date": timestamp}
    raise ValueError(f"Unsupported AMF0 marker: {marker}")


def _amf0_encode(value: Any) -> bytes:
    if value is None:
        return b"\x05"
    if isinstance(value, bool):
        return b"\x01" + bytes([value])
    if isinstance(value, (int, float)):
        return b"\x00" + struct.pack(">d", float(value))
    if isinstance(value, str):
        encoded = value.encode()
        marker = b"\x02" if len(encoded) <= 0xFFFF else b"\x0c"
        width = 2 if marker == b"\x02" else 4
        return marker + len(encoded).to_bytes(width, "big") + encoded
    if isinstance(value, list):
        return (
            b"\x0a" + len(value).to_bytes(4, "big") + b"".join(_amf0_encode(item) for item in value)
        )
    if isinstance(value, dict):
        payload = bytearray(b"\x03")
        for key, item in value.items():
            encoded_key = str(key).encode()
            payload.extend(len(encoded_key).to_bytes(2, "big") + encoded_key + _amf0_encode(item))
        return bytes(payload) + b"\x00\x00\x09"
    raise ValueError(f"Unsupported AMF0 value: {type(value).__name__}")


def _u29_decode(reader: _Reader) -> int:
    value = 0
    for _ in range(3):
        byte = reader.byte()
        if byte < 128:
            return (value << 7) | byte
        value = (value << 7) | (byte & 127)
    return (value << 8) | reader.byte()


def _u29_encode(value: int) -> bytes:
    value &= 0x1FFFFFFF
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([(value >> 7) | 0x80, value & 0x7F])
    if value < 0x200000:
        return bytes([(value >> 14) | 0x80, ((value >> 7) & 0x7F) | 0x80, value & 0x7F])
    return bytes(
        [
            (value >> 22) | 0x80,
            ((value >> 15) & 0x7F) | 0x80,
            ((value >> 8) & 0x7F) | 0x80,
            value & 0xFF,
        ]
    )


def _amf3_string(reader: _Reader) -> str:
    header = _u29_decode(reader)
    if not header & 1:
        raise ValueError("AMF3 string references are not supported")
    return reader.take(header >> 1).decode("utf-8", "replace")


def _amf3_decode(reader: _Reader) -> Any:
    marker = reader.byte()
    if marker in {0, 1}:
        return None
    if marker == 2:
        return False
    if marker == 3:
        return True
    if marker == 4:
        value = _u29_decode(reader)
        return value - 0x20000000 if value & 0x10000000 else value
    if marker == 5:
        return struct.unpack(">d", reader.take(8))[0]
    if marker == 6:
        return _amf3_string(reader)
    if marker == 9:
        header = _u29_decode(reader)
        if not header & 1:
            raise ValueError("AMF3 array references are not supported")
        dense_length = header >> 1
        associative: dict[str, Any] = {}
        while True:
            key = _amf3_string(reader)
            if not key:
                break
            associative[key] = _amf3_decode(reader)
        dense = [_amf3_decode(reader) for _ in range(dense_length)]
        return dense if not associative else {**associative, "$dense": dense}
    if marker == 10:
        traits = _u29_decode(reader)
        if traits & 3 != 3:
            raise ValueError("AMF3 object references are not supported")
        dynamic = bool(traits & 8)
        sealed_count = traits >> 4
        _amf3_string(reader)
        names = [_amf3_string(reader) for _ in range(sealed_count)]
        result = {name: _amf3_decode(reader) for name in names}
        if dynamic:
            while True:
                name = _amf3_string(reader)
                if not name:
                    break
                result[name] = _amf3_decode(reader)
        return result
    if marker == 12:
        header = _u29_decode(reader)
        return {"$bytes": base64.b64encode(reader.take(header >> 1)).decode()}
    raise ValueError(f"Unsupported AMF3 marker: {marker}")


def _amf3_string_encode(value: str) -> bytes:
    encoded = value.encode()
    return _u29_encode((len(encoded) << 1) | 1) + encoded


def _amf3_encode(value: Any) -> bytes:
    if value is None:
        return b"\x01"
    if value is False:
        return b"\x02"
    if value is True:
        return b"\x03"
    if isinstance(value, int) and -0x10000000 <= value < 0x10000000:
        return b"\x04" + _u29_encode(value)
    if isinstance(value, (int, float)):
        return b"\x05" + struct.pack(">d", float(value))
    if isinstance(value, str):
        return b"\x06" + _amf3_string_encode(value)
    if isinstance(value, list):
        return (
            b"\x09"
            + _u29_encode((len(value) << 1) | 1)
            + b"\x01"
            + b"".join(_amf3_encode(item) for item in value)
        )
    if isinstance(value, dict):
        payload = bytearray(b"\x0a\x0b\x01")
        for key, item in value.items():
            payload.extend(_amf3_string_encode(str(key)) + _amf3_encode(item))
        return bytes(payload) + b"\x01"
    raise ValueError(f"Unsupported AMF3 value: {type(value).__name__}")


@operation("AMF Decode", category="Encodings")
def amf_decode(value: Data, args: Args) -> Data:
    reader = _Reader(to_bytes(value))
    result = _amf0_decode(reader) if str(arg(args, 0, "AMF3")) == "AMF0" else _amf3_decode(reader)
    return _json_output(result)


@operation("AMF Encode", category="Encodings")
def amf_encode(value: Data, args: Args) -> Data:
    parsed = _json_input(value)
    return _amf0_encode(parsed) if str(arg(args, 0, "AMF3")) == "AMF0" else _amf3_encode(parsed)


def _varint(reader: _Reader) -> int:
    result = shift = 0
    while True:
        byte = reader.byte()
        result |= (byte & 0x7F) << shift
        if byte < 128:
            return result
        shift += 7
        if shift > 70:
            raise ValueError("Invalid varint")


def _varint_encode(value: int) -> bytes:
    value &= (1 << 64) - 1
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def _proto_schema(schema: str) -> dict[int, tuple[str, str, bool]]:
    fields: dict[int, tuple[str, str, bool]] = {}
    pattern = re.compile(r"\b(?:(repeated|required|optional)\s+)?([.\w]+)\s+(\w+)\s*=\s*(\d+)")
    for qualifier, field_type, name, number in pattern.findall(schema):
        fields[int(number)] = (name, field_type, qualifier == "repeated")
    return fields


def _proto_decode(data: bytes, schema: str, show_types: bool) -> dict[str, Any]:
    reader = _Reader(data)
    fields = _proto_schema(schema)
    result: dict[str, Any] = {}
    while reader.position < len(data):
        tag = _varint(reader)
        number, wire = tag >> 3, tag & 7
        name, field_type, repeated = fields.get(number, (str(number), "unknown", False))
        if wire == 0:
            item: Any = _varint(reader)
            if field_type in {"sint32", "sint64"}:
                item = (item >> 1) ^ -(item & 1)
            elif field_type == "bool":
                item = bool(item)
        elif wire == 1:
            raw = reader.take(8)
            item = (
                struct.unpack("<d", raw)[0]
                if field_type == "double"
                else int.from_bytes(raw, "little")
            )
        elif wire == 2:
            raw = reader.take(_varint(reader))
            if field_type == "string":
                item = raw.decode("utf-8", "replace")
            elif field_type == "bytes" or field_type == "unknown":
                item = base64.b64encode(raw).decode()
            else:
                item = _proto_decode(raw, schema, show_types)
        elif wire == 5:
            raw = reader.take(4)
            item = (
                struct.unpack("<f", raw)[0]
                if field_type == "float"
                else int.from_bytes(raw, "little")
            )
        else:
            raise ValueError(f"Unsupported protobuf wire type: {wire}")
        key = f"{name} ({field_type})" if show_types else name
        if repeated or key in result:
            current = result.setdefault(key, [])
            if not isinstance(current, list):
                result[key] = current = [current]
            current.append(item)
        else:
            result[key] = item
    return result


def _proto_encode_item(number: int, field_type: str, value: Any) -> bytes:
    if field_type in {"string", "bytes"} or isinstance(value, (str, dict)):
        if field_type == "bytes":
            raw = base64.b64decode(str(value))
        elif isinstance(value, dict):
            # A nested message needs a separate schema; keep unknown nested values empty.
            raw = b""
        else:
            raw = str(value).encode()
        return _varint_encode((number << 3) | 2) + _varint_encode(len(raw)) + raw
    if field_type == "double":
        return _varint_encode((number << 3) | 1) + struct.pack("<d", float(value))
    if field_type == "float":
        return _varint_encode((number << 3) | 5) + struct.pack("<f", float(value))
    integer = int(value)
    if field_type in {"sint32", "sint64"}:
        integer = (integer << 1) ^ (integer >> 63)
    return _varint_encode(number << 3) + _varint_encode(integer)


@operation("Protobuf Decode", category="Serialise")
def protobuf_decode(value: Data, args: Args) -> Data:
    schema = str(arg(args, 0, ""))
    show_types = bool(arg(args, 2, False))
    return _json_output(_proto_decode(to_bytes(value), schema, show_types))


@operation("Protobuf Encode", category="Serialise")
def protobuf_encode(value: Data, args: Args) -> Data:
    schema = str(arg(args, 0, ""))
    fields = _proto_schema(schema)
    by_name = {
        name: (number, field_type, repeated)
        for number, (name, field_type, repeated) in fields.items()
    }
    parsed = _json_input(value)
    if not isinstance(parsed, dict):
        raise ValueError("Protobuf input must be a JSON object")
    output = bytearray()
    for name, item in parsed.items():
        if name not in by_name:
            raise ValueError(f"Field not found in schema: {name}")
        number, field_type, repeated = by_name[name]
        values = item if repeated and isinstance(item, list) else [item]
        for entry in values:
            output.extend(_proto_encode_item(number, field_type, entry))
    return bytes(output)


def _avro_long(reader: _Reader) -> int:
    raw = _varint(reader)
    return (raw >> 1) ^ -(raw & 1)


def _avro_value(reader: _Reader, schema: Any) -> Any:
    if isinstance(schema, list):
        return _avro_value(reader, schema[_avro_long(reader)])
    if isinstance(schema, dict):
        schema_type = schema["type"]
        if schema_type == "record":
            return {field["name"]: _avro_value(reader, field["type"]) for field in schema["fields"]}
        if schema_type == "array":
            values = []
            count = _avro_long(reader)
            while count:
                if count < 0:
                    reader.take(_avro_long(reader))
                    count = -count
                values.extend(_avro_value(reader, schema["items"]) for _ in range(count))
                count = _avro_long(reader)
            return values
        if schema_type == "map":
            output: dict[str, Any] = {}
            count = _avro_long(reader)
            while count:
                if count < 0:
                    reader.take(_avro_long(reader))
                    count = -count
                for _ in range(count):
                    output[_avro_value(reader, "string")] = _avro_value(reader, schema["values"])
                count = _avro_long(reader)
            return output
        if schema_type == "enum":
            return schema["symbols"][_avro_long(reader)]
        if schema_type == "fixed":
            return base64.b64encode(reader.take(schema["size"])).decode()
        return _avro_value(reader, schema_type)
    if schema == "null":
        return None
    if schema == "boolean":
        return bool(reader.byte())
    if schema in {"int", "long"}:
        return _avro_long(reader)
    if schema == "float":
        return struct.unpack("<f", reader.take(4))[0]
    if schema == "double":
        return struct.unpack("<d", reader.take(8))[0]
    if schema in {"bytes", "string"}:
        raw = reader.take(_avro_long(reader))
        return (
            raw.decode("utf-8", "replace") if schema == "string" else base64.b64encode(raw).decode()
        )
    raise ValueError(f"Unsupported Avro schema type: {schema}")


@operation("Avro to JSON", category="Serialise")
def avro_to_json(value: Data, args: Args) -> Data:
    data = to_bytes(value)
    if not data:
        raise ValueError("Please provide an input.")
    reader = _Reader(data)
    if reader.take(4) != b"Obj\x01":
        raise ValueError("Error parsing Avro file.")
    metadata: dict[str, bytes] = {}
    count = _avro_long(reader)
    while count:
        if count < 0:
            reader.take(_avro_long(reader))
            count = -count
        for _ in range(count):
            key = _avro_value(reader, "string")
            raw = reader.take(_avro_long(reader))
            metadata[key] = raw
        count = _avro_long(reader)
    sync = reader.take(16)
    schema = json.loads(metadata["avro.schema"])
    codec = metadata.get("avro.codec", b"null").decode()
    result = []
    while reader.position < len(data):
        block_count = _avro_long(reader)
        block = reader.take(_avro_long(reader))
        if codec == "deflate":
            block = zlib.decompress(block, -15)
        block_reader = _Reader(block)
        result.extend(_avro_value(block_reader, schema) for _ in range(block_count))
        if reader.take(16) != sync:
            raise ValueError("Error parsing Avro file.")
    rendered: Any = result[0] if len(result) == 1 else result
    if bool(arg(args, 0, True)):
        return json.dumps(rendered, ensure_ascii=False, indent=4)
    return "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in result)


_SIGNATURES = (
    ("PNG image", "png", "image/png", b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", "jpg", "image/jpeg", b"\xff\xd8\xff"),
    ("PDF document", "pdf", "application/pdf", b"%PDF-"),
    ("ZIP archive", "zip", "application/zip", b"PK\x03\x04"),
    ("Gzip archive", "gz", "application/gzip", b"\x1f\x8b\x08"),
    ("ELF executable", "elf", "application/x-elf", b"\x7fELF"),
    ("MP3 with ID3", "mp3", "audio/mpeg", b"ID3"),
)


def _scan(data: bytes) -> list[tuple[int, str, str, str]]:
    found = []
    for name, extension, mime, signature in _SIGNATURES:
        position = data.find(signature)
        while position >= 0:
            found.append((position, name, extension, mime))
            position = data.find(signature, position + 1)
    return sorted(found)


def _carve_end(data: bytes, offset: int, extension: str) -> int:
    markers = {"png": b"IEND\xaeB`\x82", "jpg": b"\xff\xd9", "pdf": b"%%EOF"}
    marker = markers.get(extension)
    if marker is None:
        return len(data)
    position = data.find(marker, offset)
    return len(data) if position < 0 else position + len(marker)


@operation("Scan for Embedded Files", category="Forensics")
def scan_for_embedded_files(value: Data, args: Args) -> Data:
    del args
    found = _scan(to_bytes(value))
    header = (
        "Scanning data for 'magic bytes' which may indicate embedded files. The following results "
        "may be false positives and should not be treated as reliable. Any sufficiently long file "
        "is likely to contain these magic bytes coincidentally.\n"
    )
    if not found:
        return header + "\nNo embedded files were found."
    return header + "".join(
        f"\nOffset {offset} (0x{offset:x}):\n  File type:   {name}\n  Extension:   {extension}"
        f"\n  MIME type:   {mime}\n"
        for offset, name, extension, mime in found
    )


@operation("Extract Files", category="Forensics")
def extract_files(value: Data, args: Args) -> Data:
    data = to_bytes(value)
    minimum = int(args[-1]) if args and isinstance(args[-1], (int, float)) else 100
    files = []
    for index, (offset, name, extension, mime) in enumerate(_scan(data), 1):
        carved = data[offset : _carve_end(data, offset, extension)]
        if len(carved) >= minimum:
            files.append(
                {
                    "name": f"extracted_{index}.{extension}",
                    "type": name,
                    "mime": mime,
                    "offset": offset,
                    "size": len(carved),
                    "data": base64.b64encode(carved).decode(),
                }
            )
    return _json_output(files)


@operation("File Tree", category="Text")
def file_tree(value: Data, args: Args) -> Data:
    path_delimiter = str(arg(args, 0, "/"))
    entry_delimiter = char_rep(arg(args, 1, "Line feed"), "\n")
    completed: set[str] = set()
    lines = []
    for file_path in sorted(set(to_text(value).split(entry_delimiter))):
        path = file_path.split(path_delimiter)
        if path and path[0] == "":
            path = path[1:]
        for index, component in enumerate(path):
            key = "/".join(path[: index + 1])
            if key in completed:
                continue
            completed.add(key)
            lines.append(component if index == 0 else "|   " * (index - 1) + "|---" + component)
    return "\n".join(lines)


_ID3_NAMES = {"TIT2": "Title", "TPE1": "Artist", "TALB": "Album", "TRCK": "Track", "TCON": "Genre"}


def _synchsafe(data: bytes) -> int:
    return sum((byte & 0x7F) << (7 * (len(data) - index - 1)) for index, byte in enumerate(data))


def _id3(data: bytes) -> dict[str, Any]:
    if len(data) < 10 or data[:3] != b"ID3":
        raise ValueError("No valid ID3 header.")
    size = _synchsafe(data[6:10])
    result: dict[str, Any] = {
        "Type": "ID3",
        "Version": f"{data[3]}.{data[4]}",
        "Flags": str(data[5]),
        "Size": str(size),
        "Tags": {},
    }
    position = 10
    end = min(len(data), 10 + size)
    while position + 10 <= end and data[position] != 0:
        identifier = data[position : position + 4].decode("latin-1")
        frame_size = int.from_bytes(data[position + 4 : position + 8], "big")
        payload = data[position + 10 : position + 10 + frame_size]
        encoding = payload[:1]
        codec = "utf-16" if encoding in {b"\x01", b"\x02"} else "utf-8"
        decoded = payload[1:].rstrip(b"\0").decode(codec, "replace") if payload else ""
        result["Tags"][identifier] = {
            "Size": str(frame_size),
            "Description": _ID3_NAMES.get(identifier, identifier),
            "Data": decoded,
        }
        position += 10 + frame_size
    return result


@operation("Extract ID3", category="Forensics")
def extract_id3(value: Data, args: Args) -> Data:
    del args
    return _json_output(_id3(to_bytes(value)))


@operation("Extract Audio Metadata", category="Forensics")
def extract_audio_metadata(value: Data, args: Args) -> Data:
    data = to_bytes(value)
    if not data:
        raise ValueError("No input data. Load an audio file.")
    filename = str(arg(args, 0, "")) or None
    if data.startswith(b"ID3"):
        container, mime = "mp3", "audio/mpeg"
    elif data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        container, mime = "wav", "audio/wav"
    elif data.startswith(b"fLaC"):
        container, mime = "flac", "audio/flac"
    elif data.startswith(b"OggS"):
        container, mime = "ogg", "audio/ogg"
    else:
        container, mime = "unknown", "application/octet-stream"
    tags: dict[str, Any] = {}
    errors = []
    if container == "mp3":
        try:
            tags = _id3(data)
        except ValueError as exc:
            errors.append({"stage": "parse", "message": str(exc)})
    return _json_output(
        {
            "artifact": {
                "filename": filename,
                "byte_length": len(data),
                "container": {"type": container, "mime": mime},
            },
            "tags": tags,
            "errors": errors,
        }
    )


_EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
}


def _jpeg_exif(data: bytes) -> bytes | None:
    if not data.startswith(b"\xff\xd8"):
        return None
    position = 2
    while position + 4 <= len(data) and data[position] == 0xFF:
        marker = data[position + 1]
        if marker in {0xDA, 0xD9}:
            break
        length = int.from_bytes(data[position + 2 : position + 4], "big")
        segment = data[position + 4 : position + 2 + length]
        if marker == 0xE1 and segment.startswith(b"Exif\0\0"):
            return segment[6:]
        position += 2 + length
    return None


def _exif_tags(tiff: bytes) -> dict[str, Any]:
    if len(tiff) < 8 or tiff[:2] not in {b"II", b"MM"}:
        raise ValueError("Invalid TIFF header")
    order = "little" if tiff[:2] == b"II" else "big"
    offset = int.from_bytes(tiff[4:8], order)
    count = int.from_bytes(tiff[offset : offset + 2], order)
    tags: dict[str, Any] = {}
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}
    for index in range(count):
        entry = tiff[offset + 2 + index * 12 : offset + 14 + index * 12]
        if len(entry) != 12:
            break
        tag = int.from_bytes(entry[:2], order)
        kind = int.from_bytes(entry[2:4], order)
        amount = int.from_bytes(entry[4:8], order)
        length = sizes.get(kind, 1) * amount
        raw = (
            entry[8:12][:length]
            if length <= 4
            else tiff[int.from_bytes(entry[8:12], order) :][:length]
        )
        if kind == 2:
            item: Any = raw.rstrip(b"\0").decode("utf-8", "replace")
        elif kind in {3, 4}:
            item = int.from_bytes(raw[: sizes[kind]], order)
        else:
            item = raw.hex()
        tags[_EXIF_TAGS.get(tag, f"Tag_0x{tag:04x}")] = item
    return tags


@operation("Extract EXIF", category="Image")
def extract_exif(value: Data, args: Args) -> Data:
    del args
    data = to_bytes(value)
    tiff = _jpeg_exif(data) or (data if data[:2] in {b"II", b"MM"} else None)
    if tiff is None:
        raise ValueError("Could not extract EXIF data from image: Exif not found.")
    tags = _exif_tags(tiff)
    return f"Found {len(tags)} tags.\n\n" + "\n".join(
        f"{key}: {item}" for key, item in tags.items()
    )


@operation("Remove EXIF", category="Image")
def remove_exif(value: Data, args: Args) -> Data:
    del args
    data = to_bytes(value)
    if not data or not data.startswith(b"\xff\xd8"):
        return data
    output = bytearray(data[:2])
    position = 2
    while position + 4 <= len(data) and data[position] == 0xFF:
        marker = data[position + 1]
        if marker in {0xDA, 0xD9}:
            output.extend(data[position:])
            return bytes(output)
        length = int.from_bytes(data[position + 2 : position + 4], "big")
        end = position + 2 + length
        segment = data[position + 4 : end]
        if marker != 0xE1 or not segment.startswith(b"Exif\0\0"):
            output.extend(data[position:end])
        position = end
    output.extend(data[position:])
    return bytes(output)
