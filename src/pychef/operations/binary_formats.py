"""Small, dependency-free CBOR, MessagePack, and BSON codecs."""

from __future__ import annotations

import json
import math
import struct
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text

_MAX_CONTAINER_ITEMS = 1_000_000
_MAX_DEPTH = 100


def _load_json(value: Data) -> Any:
    return json.loads(to_text(value))


def _json_output(value: Any, *, indent: int) -> str:
    return json.dumps(value, ensure_ascii=False, indent=indent, separators=(",", ": "))


def _sized_integer(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", value)
    raise ValueError("integer exceeds the supported 64-bit CBOR range")


def _cbor_encode(value: Any, depth: int = 0) -> bytes:
    if depth > _MAX_DEPTH:
        raise ValueError("CBOR nesting is too deep")
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return _sized_integer(0, value) if value >= 0 else _sized_integer(1, -1 - value)
    if isinstance(value, float):
        if math.isnan(value):
            return b"\xf9\x7e\x00"
        try:
            half = struct.pack(">e", value)
        except (OverflowError, struct.error):
            half = b""
        if half and struct.unpack(">e", half)[0] == value:
            return b"\xf9" + half
        single = struct.pack(">f", value)
        if struct.unpack(">f", single)[0] == value:
            return b"\xfa" + single
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, str):
        encoded = value.encode()
        return _sized_integer(3, len(encoded)) + encoded
    if isinstance(value, bytes):
        return _sized_integer(2, len(value)) + value
    if isinstance(value, list):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise ValueError("CBOR array is too large")
        return _sized_integer(4, len(value)) + b"".join(
            _cbor_encode(item, depth + 1) for item in value
        )
    if isinstance(value, dict):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise ValueError("CBOR map is too large")
        return _sized_integer(5, len(value)) + b"".join(
            _cbor_encode(key, depth + 1) + _cbor_encode(item, depth + 1)
            for key, item in value.items()
        )
    raise ValueError(f"unsupported CBOR value: {type(value).__name__}")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def read(self, count: int) -> bytes:
        if count < 0 or self.position + count > len(self.data):
            raise ValueError("truncated binary input")
        result = self.data[self.position : self.position + count]
        self.position += count
        return result

    def byte(self) -> int:
        return self.read(1)[0]


def _cbor_length(reader: _Reader, additional: int) -> int:
    if additional < 24:
        return additional
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional not in sizes:
        raise ValueError("indefinite or reserved CBOR length is unsupported")
    return int.from_bytes(reader.read(sizes[additional]), "big")


def _cbor_decode(reader: _Reader, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("CBOR nesting is too deep")
    initial = reader.byte()
    major, additional = initial >> 5, initial & 31
    if major in {0, 1}:
        value = _cbor_length(reader, additional)
        return value if major == 0 else -1 - value
    if major in {2, 3}:
        length = _cbor_length(reader, additional)
        raw = reader.read(length)
        return raw if major == 2 else raw.decode()
    if major == 4:
        length = _cbor_length(reader, additional)
        if length > _MAX_CONTAINER_ITEMS:
            raise ValueError("CBOR array is too large")
        return [_cbor_decode(reader, depth + 1) for _ in range(length)]
    if major == 5:
        length = _cbor_length(reader, additional)
        if length > _MAX_CONTAINER_ITEMS:
            raise ValueError("CBOR map is too large")
        return {
            _cbor_decode(reader, depth + 1): _cbor_decode(reader, depth + 1) for _ in range(length)
        }
    if major == 6:
        _cbor_length(reader, additional)
        return _cbor_decode(reader, depth + 1)
    if additional == 20:
        return False
    if additional == 21:
        return True
    if additional in {22, 23}:
        return None
    if additional == 25:
        return struct.unpack(">e", reader.read(2))[0]
    if additional == 26:
        return struct.unpack(">f", reader.read(4))[0]
    if additional == 27:
        return struct.unpack(">d", reader.read(8))[0]
    raise ValueError("unsupported CBOR simple value")


@operation("CBOR Encode", category="Serialisation")
def cbor_encode(value: Data, _args: Args) -> bytes:
    return _cbor_encode(_load_json(value))


@operation("CBOR Decode", category="Serialisation")
def cbor_decode(value: Data, _args: Args) -> str:
    reader = _Reader(to_bytes(value))
    decoded = _cbor_decode(reader)
    if reader.position != len(reader.data):
        raise ValueError("trailing bytes after CBOR value")
    return _json_output(decoded, indent=4)


def _msgpack_encode(value: Any, depth: int = 0) -> bytes:
    if depth > _MAX_DEPTH:
        raise ValueError("MessagePack nesting is too deep")
    if value is None:
        return b"\xc0"
    if value is False:
        return b"\xc2"
    if value is True:
        return b"\xc3"
    if isinstance(value, int):
        if 0 <= value <= 0x7F:
            return bytes([value])
        if -32 <= value < 0:
            return bytes([value & 0xFF])
        for minimum, maximum, marker, format_ in (
            (0, 0xFF, 0xCC, ">B"),
            (0, 0xFFFF, 0xCD, ">H"),
            (0, 0xFFFFFFFF, 0xCE, ">I"),
            (0, 0xFFFFFFFFFFFFFFFF, 0xCF, ">Q"),
            (-0x80, -1, 0xD0, ">b"),
            (-0x8000, -1, 0xD1, ">h"),
            (-0x80000000, -1, 0xD2, ">i"),
            (-0x8000000000000000, -1, 0xD3, ">q"),
        ):
            if minimum <= value <= maximum:
                return bytes([marker]) + struct.pack(format_, value)
        raise ValueError("integer exceeds MessagePack's 64-bit range")
    if isinstance(value, float):
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        data = value.encode()
        length = len(data)
        if length < 32:
            return bytes([0xA0 | length]) + data
        if length <= 0xFF:
            return b"\xd9" + bytes([length]) + data
        if length <= 0xFFFF:
            return b"\xda" + struct.pack(">H", length) + data
        return b"\xdb" + struct.pack(">I", length) + data
    if isinstance(value, bytes):
        length = len(value)
        if length <= 0xFF:
            return b"\xc4" + bytes([length]) + value
        if length <= 0xFFFF:
            return b"\xc5" + struct.pack(">H", length) + value
        return b"\xc6" + struct.pack(">I", length) + value
    if isinstance(value, list):
        length = len(value)
        prefix = (
            bytes([0x90 | length])
            if length < 16
            else b"\xdc" + struct.pack(">H", length)
            if length <= 0xFFFF
            else b"\xdd" + struct.pack(">I", length)
        )
        return prefix + b"".join(_msgpack_encode(item, depth + 1) for item in value)
    if isinstance(value, dict):
        length = len(value)
        prefix = (
            bytes([0x80 | length])
            if length < 16
            else b"\xde" + struct.pack(">H", length)
            if length <= 0xFFFF
            else b"\xdf" + struct.pack(">I", length)
        )
        return prefix + b"".join(
            _msgpack_encode(key, depth + 1) + _msgpack_encode(item, depth + 1)
            for key, item in value.items()
        )
    raise ValueError(f"unsupported MessagePack value: {type(value).__name__}")


def _unpack_number(reader: _Reader, format_: str) -> int | float:
    return struct.unpack(format_, reader.read(struct.calcsize(format_)))[0]


def _msgpack_decode(reader: _Reader, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("MessagePack nesting is too deep")
    marker = reader.byte()
    if marker <= 0x7F:
        return marker
    if marker >= 0xE0:
        return marker - 256
    if 0xA0 <= marker <= 0xBF:
        return reader.read(marker & 31).decode()
    if 0x90 <= marker <= 0x9F:
        return [_msgpack_decode(reader, depth + 1) for _ in range(marker & 15)]
    if 0x80 <= marker <= 0x8F:
        return {
            _msgpack_decode(reader, depth + 1): _msgpack_decode(reader, depth + 1)
            for _ in range(marker & 15)
        }
    if marker == 0xC0:
        return None
    if marker in {0xC2, 0xC3}:
        return marker == 0xC3
    numeric = {
        0xCA: ">f",
        0xCB: ">d",
        0xCC: ">B",
        0xCD: ">H",
        0xCE: ">I",
        0xCF: ">Q",
        0xD0: ">b",
        0xD1: ">h",
        0xD2: ">i",
        0xD3: ">q",
    }
    if marker in numeric:
        return _unpack_number(reader, numeric[marker])
    if marker in {0xC4, 0xC5, 0xC6, 0xD9, 0xDA, 0xDB}:
        width = {0xC4: 1, 0xC5: 2, 0xC6: 4, 0xD9: 1, 0xDA: 2, 0xDB: 4}[marker]
        raw = reader.read(int.from_bytes(reader.read(width), "big"))
        return raw if marker in {0xC4, 0xC5, 0xC6} else raw.decode()
    if marker in {0xDC, 0xDD}:
        length = int.from_bytes(reader.read(2 if marker == 0xDC else 4), "big")
        if length > _MAX_CONTAINER_ITEMS:
            raise ValueError("MessagePack array is too large")
        return [_msgpack_decode(reader, depth + 1) for _ in range(length)]
    if marker in {0xDE, 0xDF}:
        length = int.from_bytes(reader.read(2 if marker == 0xDE else 4), "big")
        if length > _MAX_CONTAINER_ITEMS:
            raise ValueError("MessagePack map is too large")
        return {
            _msgpack_decode(reader, depth + 1): _msgpack_decode(reader, depth + 1)
            for _ in range(length)
        }
    raise ValueError(f"unsupported MessagePack marker: 0x{marker:02x}")


@operation("To MessagePack", category="Serialisation")
def to_messagepack(value: Data, _args: Args) -> bytes:
    return _msgpack_encode(_load_json(value))


@operation("From MessagePack", category="Serialisation")
def from_messagepack(value: Data, _args: Args) -> str:
    reader = _Reader(to_bytes(value))
    decoded = _msgpack_decode(reader)
    if reader.position != len(reader.data):
        raise ValueError("trailing bytes after MessagePack value")
    return _json_output(decoded, indent=4)


def _bson_cstring(value: str) -> bytes:
    if "\0" in value:
        raise ValueError("BSON keys cannot contain NUL")
    return value.encode() + b"\0"


def _bson_element(key: str, value: Any, depth: int) -> bytes:
    name = _bson_cstring(key)
    if value is None:
        return b"\x0a" + name
    if value is False or value is True:
        return b"\x08" + name + bytes([value])
    if isinstance(value, float):
        return b"\x01" + name + struct.pack("<d", value)
    if isinstance(value, int):
        if -0x80000000 <= value <= 0x7FFFFFFF:
            return b"\x10" + name + struct.pack("<i", value)
        return b"\x12" + name + struct.pack("<q", value)
    if isinstance(value, str):
        encoded = value.encode() + b"\0"
        return b"\x02" + name + struct.pack("<i", len(encoded)) + encoded
    if isinstance(value, dict):
        return b"\x03" + name + _bson_document(value, depth + 1)
    if isinstance(value, list):
        return b"\x04" + name + _bson_document(dict(enumerate(value)), depth + 1)
    raise ValueError(f"unsupported BSON value: {type(value).__name__}")


def _bson_document(value: dict[Any, Any], depth: int = 0) -> bytes:
    if depth > _MAX_DEPTH:
        raise ValueError("BSON nesting is too deep")
    body = b"".join(_bson_element(str(key), item, depth) for key, item in value.items()) + b"\0"
    return struct.pack("<i", len(body) + 4) + body


def _read_cstring(reader: _Reader) -> str:
    end = reader.data.find(b"\0", reader.position)
    if end < 0:
        raise ValueError("unterminated BSON key")
    value = reader.data[reader.position : end].decode()
    reader.position = end + 1
    return value


def _bson_decode_document(reader: _Reader, depth: int = 0) -> dict[str, Any]:
    if depth > _MAX_DEPTH:
        raise ValueError("BSON nesting is too deep")
    start = reader.position
    length = struct.unpack("<i", reader.read(4))[0]
    if length < 5 or start + length > len(reader.data):
        raise ValueError("invalid BSON document length")
    end = start + length
    output: dict[str, Any] = {}
    while reader.position < end - 1:
        kind = reader.byte()
        key = _read_cstring(reader)
        if kind == 0x01:
            item: Any = _unpack_number(reader, "<d")
        elif kind == 0x02:
            size = struct.unpack("<i", reader.read(4))[0]
            raw = reader.read(size)
            if size < 1 or raw[-1:] != b"\0":
                raise ValueError("invalid BSON string")
            item = raw[:-1].decode()
        elif kind in {0x03, 0x04}:
            nested = _bson_decode_document(reader, depth + 1)
            item = [nested[str(index)] for index in range(len(nested))] if kind == 0x04 else nested
        elif kind == 0x08:
            item = bool(reader.byte())
        elif kind == 0x0A:
            item = None
        elif kind == 0x10:
            item = _unpack_number(reader, "<i")
        elif kind == 0x12:
            item = _unpack_number(reader, "<q")
        else:
            raise ValueError(f"unsupported BSON element type: 0x{kind:02x}")
        output[key] = item
    if reader.byte() != 0 or reader.position != end:
        raise ValueError("invalid BSON document terminator")
    return output


@operation("BSON serialise", category="Serialisation")
def bson_serialize(value: Data, _args: Args) -> bytes:
    if not to_bytes(value):
        return b""
    parsed = _load_json(value)
    if not isinstance(parsed, dict):
        raise ValueError("top-level BSON input must be a JSON object")
    return _bson_document(parsed)


@operation("BSON deserialise", category="Serialisation")
def bson_deserialize(value: Data, _args: Args) -> str:
    if not to_bytes(value):
        return ""
    reader = _Reader(to_bytes(value))
    decoded = _bson_decode_document(reader)
    if reader.position != len(reader.data):
        raise ValueError("trailing bytes after BSON document")
    return _json_output(decoded, indent=2)
