"""Official vectors for additional encodings ported from CyberChef."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("source", "encoded"),
    [("", ""), ("AB", "BB8"), ("Hello!!", "%69 VD92EX0"), ("base-45", "UJCLQE7W581")],
)
def test_base45_official_vectors(source: str, encoded: str) -> None:
    alphabet = "0-9A-Z $%*+\\-./:"
    assert bake(source, [{"op": "To Base45", "args": [alphabet]}]) == encoded
    assert bake(encoded, [{"op": "From Base45", "args": [alphabet]}]) == source.encode()


def test_base45_official_decode_and_invalid_values() -> None:
    args = ["0-9A-Z $%*+\\-./:", False]
    assert bake("QED8WEX0", [{"op": "From Base45", "args": args}]) == b"ietf!"
    with pytest.raises(OperationError, match="character not in alphabet"):
        bake("!", [{"op": "From Base45", "args": args}])
    with pytest.raises(OperationError, match="triplet too large"):
        bake("ZZZ", [{"op": "From Base45", "args": args}])


@pytest.mark.parametrize(
    ("raw", "encoded"),
    [
        (b"\x00", b"\x01\x01"),
        (b"\x00\x00", b"\x01\x01\x01"),
        (b"\x00\x11\x00", b"\x01\x02\x11\x01"),
        (b"\x11\x22\x00\x33", b"\x03\x11\x22\x02\x33"),
        (b"\x11\x22\x33\x44", b"\x05\x11\x22\x33\x44"),
        (b"\x11\x00\x00\x00", b"\x02\x11\x01\x01\x01"),
    ],
)
def test_cobs_official_vectors(raw: bytes, encoded: bytes) -> None:
    assert bake(raw, ["To COBS"]) == encoded
    assert bake(encoded, ["From COBS"]) == raw


def test_cobs_long_block_and_invalid_data() -> None:
    raw = bytes(range(1, 256))
    encoded = bake(raw, ["To COBS"])
    assert isinstance(encoded, bytes)
    assert encoded[:1] == b"\xff"
    assert bake(encoded, ["From COBS"]) == raw
    with pytest.raises(OperationError, match="invalid COBS"):
        bake(b"\x00", ["From COBS"])


def test_bcd_official_vectors() -> None:
    assert bake("0", [{"op": "To BCD", "args": ["8 4 2 1", True, False, "Nibbles"]}]) == "0000"
    unpacked = bake("1234567890", [{"op": "To BCD", "args": ["8 4 2 1", False, False, "Nibbles"]}])
    assert unpacked == (
        "0000 0001 0000 0010 0000 0011 0000 0100 0000 0101 "
        "0000 0110 0000 0111 0000 1000 0000 1001 0000 0000"
    )
    signed = bake("1234567890", [{"op": "To BCD", "args": ["8 4 2 1", True, True, "Bytes"]}])
    assert signed == "00000001 00100011 01000101 01100111 10001001 00001100"
    assert (
        bake(
            "00000001 00100011 01000101 01100111 10001001 00001101",
            [{"op": "From BCD", "args": ["8 4 2 1", True, True, "Bytes"]}],
        )
        == "-1234567890"
    )


def test_bcd_raw_round_trip_and_presentation_encodings() -> None:
    raw = bake("1234567890", [{"op": "To BCD", "args": ["4 2 2 1", True, True, "Raw"]}])
    assert isinstance(raw, bytes)
    assert bake(raw, [{"op": "From BCD", "args": ["4 2 2 1", True, True, "Raw"]}]) == "1234567890"
    braille = bake("HELLO 123", ["To Braille"])
    assert bake(braille, ["From Braille"]) == "HELLO 123"
    dump = bake(b"Hello\x00World", [{"op": "To Hexdump", "args": [8, False, True, False]}])
    assert bake(dump, ["From Hexdump"]) == b"Hello\x00World"


def test_regex_unicode_and_parity_helpers() -> None:
    pattern = bake("Ab-1", ["To Case Insensitive Regex"])
    assert pattern == "[aA]b-1"
    assert bake(pattern, ["From Case Insensitive Regex"]) == "ab-1"
    assert bake("x", [{"op": "Unicode Text Format", "args": [True, True]}]) == "x\u0336\u0332"
    encoded = bake(
        "1011001", [{"op": "Parity Bit", "args": ["Even Parity", "Start", "Encode", ""]}]
    )
    assert (
        bake(encoded, [{"op": "Parity Bit", "args": ["Even Parity", "Start", "Decode", ""]}])
        == "1011001"
    )
