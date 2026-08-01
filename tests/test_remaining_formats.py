"""Tests for structured formats, metadata, and file carving operations."""

from __future__ import annotations

import base64
import json
import struct
from collections.abc import Sequence
from typing import Any

import pytest

from pychef import registry
from pychef.operations import remaining_formats as formats


def run(name: str, value: str | bytes, args: Sequence[Any] | None = None) -> Any:
    return registry.get(name).run(value, args or [])


@pytest.mark.parametrize("version", ["AMF0", "AMF3"])
@pytest.mark.parametrize(
    "value",
    [None, True, False, 12, -2, 1.25, "Grüße", [1, "two", None], {"a": 1, "b": True}],
)
def test_amf_round_trip(version: str, value: object) -> None:
    encoded = run("AMF Encode", json.dumps(value), [version])
    decoded = json.loads(run("AMF Decode", encoded, [version]))
    assert decoded == value


def test_amf_special_decoders_and_errors() -> None:
    date = b"\x0b" + struct.pack(">d", 1234.0) + b"\0\0"
    assert json.loads(run("AMF Decode", date, ["AMF0"])) == {"$date": 1234.0}
    long_text = "x" * 65536
    assert (
        json.loads(run("AMF Decode", run("AMF Encode", json.dumps(long_text), ["AMF0"]), ["AMF0"]))
        == long_text
    )
    assert json.loads(run("AMF Decode", b"\x0c\x0fpayload", ["AMF3"])) == {"$bytes": "cGF5bG9hZA=="}
    with pytest.raises(ValueError):
        run("AMF Decode", b"\xff", ["AMF0"])
    with pytest.raises(ValueError):
        formats._amf3_encode(object())


def test_amf3_reference_tables_and_extended_markers() -> None:
    string_reference = b"\x09\x05\x01\x06\x09same\x06\x00"
    assert json.loads(run("AMF Decode", string_reference, ["AMF3"])) == ["same", "same"]

    object_reference = b"\x09\x05\x01\x0a\x0b\x01\x03x\x04\x01\x01\x0a\x02"
    assert json.loads(run("AMF Decode", object_reference, ["AMF3"])) == [{"x": 1}, {"x": 1}]

    trait_reference = b"\x09\x05\x01\x0a\x13\x01\x03x\x04\x01\x0a\x01\x04\x02"
    assert json.loads(run("AMF Decode", trait_reference, ["AMF3"])) == [{"x": 1}, {"x": 2}]

    date = b"\x08\x01" + struct.pack(">d", 1234.5)
    assert json.loads(run("AMF Decode", date, ["AMF3"])) == {"$date": 1234.5}

    vector = b"\x0d\x05\x01" + struct.pack(">ii", -1, 2)
    assert json.loads(run("AMF Decode", vector, ["AMF3"])) == {
        "$vector": "int",
        "$fixed": True,
        "$values": [-1, 2],
    }

    dictionary = b"\x11\x03\x00\x06\x03k\x04\x07"
    assert json.loads(run("AMF Decode", dictionary, ["AMF3"])) == {
        "$weak": False,
        "$entries": [["k", 7]],
    }


def test_protobuf_schema_round_trip_and_wire_types() -> None:
    schema = """
        message Example {
          string name = 1;
          int32 count = 2;
          repeated uint32 values = 3;
          fixed32 flags = 4;
          double ratio = 5;
          bytes raw = 6;
        }
    """
    source = {
        "name": "test",
        "count": -2,
        "values": [1, 150],
        "flags": 0x12345678,
        "ratio": 1.5,
        "raw": base64.b64encode(b"abc").decode(),
    }
    encoded = run("Protobuf Encode", json.dumps(source), [schema])
    decoded = json.loads(run("Protobuf Decode", encoded, [schema, False]))
    assert decoded["name"] == "test"
    assert decoded["count"] == -2
    assert decoded["values"] == [1, 150]
    assert decoded["flags"] == 0x12345678
    assert decoded["ratio"] == pytest.approx(1.5)
    assert decoded["raw"] == source["raw"]

    untyped = json.loads(run("Protobuf Decode", b"\x08\x96\x01\x12\x03abc", ["", "", True]))
    assert untyped["1 (unknown)"] == 150
    assert untyped["2 (unknown)"] == base64.b64encode(b"abc").decode()
    with pytest.raises(ValueError):
        run("Protobuf Encode", "[]", [schema])
    with pytest.raises(ValueError):
        run("Protobuf Decode", b"\x0f", [schema])


def avro_long(value: int) -> bytes:
    unsigned = (value << 1) ^ (value >> 63)
    output = bytearray()
    while unsigned >= 128:
        output.append((unsigned & 127) | 128)
        unsigned >>= 7
    output.append(unsigned)
    return bytes(output)


def avro_bytes(value: bytes) -> bytes:
    return avro_long(len(value)) + value


def test_avro_ocf_record_array_map_union_and_enum() -> None:
    schema = {
        "type": "record",
        "name": "Test",
        "fields": [
            {"name": "name", "type": "string"},
            {"name": "count", "type": "long"},
            {"name": "enabled", "type": "boolean"},
            {"name": "items", "type": {"type": "array", "items": "int"}},
            {"name": "meta", "type": {"type": "map", "values": "string"}},
            {"name": "choice", "type": ["null", "string"]},
            {"name": "kind", "type": {"type": "enum", "name": "K", "symbols": ["A", "B"]}},
            {"name": "fixed", "type": {"type": "fixed", "name": "F", "size": 2}},
        ],
    }
    schema_data = json.dumps(schema, separators=(",", ":")).encode()
    metadata = avro_long(2)
    metadata += avro_bytes(b"avro.schema") + avro_bytes(schema_data)
    metadata += avro_bytes(b"avro.codec") + avro_bytes(b"null") + avro_long(0)
    marker = bytes(range(16))
    record = avro_bytes(b"hello") + avro_long(7) + b"\x01"
    record += avro_long(2) + avro_long(1) + avro_long(2) + avro_long(0)
    record += avro_long(1) + avro_bytes(b"key") + avro_bytes(b"value") + avro_long(0)
    record += avro_long(1) + avro_bytes(b"selected") + avro_long(1) + b"xy"
    container = (
        b"Obj\x01" + metadata + marker + avro_long(1) + avro_long(len(record)) + record + marker
    )
    decoded = json.loads(run("Avro to JSON", container))
    assert decoded == {
        "name": "hello",
        "count": 7,
        "enabled": True,
        "items": [1, 2],
        "meta": {"key": "value"},
        "choice": "selected",
        "kind": "B",
        "fixed": base64.b64encode(b"xy").decode(),
    }
    with pytest.raises(ValueError):
        run("Avro to JSON", b"not-avro")


def test_file_scanning_extraction_and_tree() -> None:
    png = run("Generate Image", b"\xff\0\0", ["RGB", 1, 1])
    assert isinstance(png, bytes)
    blob = b"prefix" + png + b"suffix"
    scan = run("Scan for Embedded Files", blob)
    assert "File type:   PNG image" in scan
    assert "Offset 6" in scan
    extracted = json.loads(run("Extract Files", blob, [0]))
    assert base64.b64decode(extracted[0]["data"]).startswith(b"\x89PNG")
    tree = run("File Tree", "root/a.txt\nroot/sub/b.txt")
    assert tree == "root\n|---a.txt\n|---sub\n|   |---b.txt"
    assert "No embedded files were found" in run("Scan for Embedded Files", b"nothing")


def synchsafe(value: int) -> bytes:
    return bytes((value >> 21 & 127, value >> 14 & 127, value >> 7 & 127, value & 127))


def test_id3_and_audio_metadata() -> None:
    title = b"\x03Example"
    frame = b"TIT2" + len(title).to_bytes(4, "big") + b"\0\0" + title
    tag = b"ID3\x03\0\0" + synchsafe(len(frame)) + frame
    parsed = json.loads(run("Extract ID3", tag))
    assert parsed["Tags"]["TIT2"]["Data"] == "Example"
    metadata = json.loads(run("Extract Audio Metadata", tag, ["track.mp3"]))
    assert metadata["artifact"]["container"]["type"] == "mp3"
    assert metadata["tags"]["Tags"]["TIT2"]["Data"] == "Example"
    wav = b"RIFF" + (4).to_bytes(4, "little") + b"WAVE"
    assert json.loads(run("Extract Audio Metadata", wav))["artifact"]["container"]["type"] == "wav"
    with pytest.raises(ValueError):
        run("Extract ID3", b"missing")


def exif_jpeg() -> bytes:
    tiff = b"II*\0" + (8).to_bytes(4, "little")
    tiff += (1).to_bytes(2, "little")
    tiff += (0x010F).to_bytes(2, "little") + (2).to_bytes(2, "little")
    tiff += (6).to_bytes(4, "little") + (26).to_bytes(4, "little")
    tiff += b"\0\0\0\0" + b"Canon\0"
    payload = b"Exif\0\0" + tiff
    return b"\xff\xd8\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload + b"\xff\xd9"


def test_extract_and_remove_exif() -> None:
    jpeg = exif_jpeg()
    assert "Make: Canon" in run("Extract EXIF", jpeg)
    removed = run("Remove EXIF", jpeg)
    assert removed == b"\xff\xd8\xff\xd9"
    with pytest.raises(ValueError):
        run("Extract EXIF", removed)
