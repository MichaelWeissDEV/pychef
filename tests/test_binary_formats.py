"""Official CBOR/BSON vectors plus MessagePack interoperability vectors."""

from __future__ import annotations

import json

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("15", "0f"),
        ("1.5", "f93e00"),
        ('"Text"', "6454657874"),
        ("true", "f5"),
        ("false", "f4"),
        ('{"a":1,"b":2,"c":3}', "a3616101616202616303"),
        ("[0,1,2]", "83000102"),
    ],
)
def test_cbor_official_encode_vectors(source: str, expected: str) -> None:
    result = bake(source, ["CBOR Encode"])
    assert isinstance(result, bytes)
    assert result.hex() == expected


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        ("0f", 15),
        ("f93e00", 1.5),
        ("6454657874", "Text"),
        ("f5", True),
        ("f4", False),
        ("a3616101616202616303", {"a": 1, "b": 2, "c": 3}),
        ("83000102", [0, 1, 2]),
    ],
)
def test_cbor_official_decode_vectors(encoded: str, expected: object) -> None:
    assert json.loads(bake(bytes.fromhex(encoded), ["CBOR Decode"])) == expected


def test_cbor_round_trip_and_malformed_input() -> None:
    source = '{"a":1,"b":false,"c":[1,2,3],"d":null}'
    assert json.loads(bake(bake(source, ["CBOR Encode"]), ["CBOR Decode"])) == json.loads(source)
    with pytest.raises(OperationError, match="truncated"):
        bake(b"\x1a\0", ["CBOR Decode"])


def test_bson_official_vectors() -> None:
    expected = b"\x16\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00\x00"
    assert bake('{"hello":"world"}', ["BSON serialise"]) == expected
    assert json.loads(bake(expected, ["BSON deserialise"])) == {"hello": "world"}
    assert bake("", ["BSON serialise"]) == b""
    assert bake(b"", ["BSON deserialise"]) == ""


def test_bson_nested_round_trip_and_length_validation() -> None:
    source = '{"number":42,"large":4294967296,"ok":true,"items":[1,"x",null],"nested":{"x":1.5}}'
    encoded = bake(source, ["BSON serialise"])
    assert json.loads(bake(encoded, ["BSON deserialise"])) == json.loads(source)
    with pytest.raises(OperationError, match="document length"):
        bake(b"\x04\0\0\0", ["BSON deserialise"])


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("null", "c0"),
        ("true", "c3"),
        ("127", "7f"),
        ("128", "cc80"),
        ("-1", "ff"),
        ('"hello"', "a568656c6c6f"),
        ("[1,2,3]", "93010203"),
        ('{"a":1}', "81a16101"),
        ("1.5", "cb3ff8000000000000"),
    ],
)
def test_messagepack_vectors(source: str, expected: str) -> None:
    encoded = bake(source, ["To MessagePack"])
    assert isinstance(encoded, bytes)
    assert encoded.hex() == expected
    assert json.loads(bake(encoded, ["From MessagePack"])) == json.loads(source)


def test_messagepack_nested_round_trip_and_malformed_input() -> None:
    source = '{"store":{"books":[{"title":"PyChef","price":8.95}]},"active":true}'
    encoded = bake(source, ["To MessagePack"])
    assert json.loads(bake(encoded, ["From MessagePack"])) == json.loads(source)
    with pytest.raises(OperationError, match="truncated"):
        bake(b"\xda\x00", ["From MessagePack"])
