"""C-speed fast paths must be byte-for-byte equivalent to the straightforward definitions."""

from __future__ import annotations

import random
from typing import get_args

import pytest

from pychef import bake, ctf
from pychef._bytes import xor_repeating
from pychef.operations._utils import char_rep
from pychef.ops import from_hex, to_hex, xor
from pychef.ops.encoding import HexOutputDelimiter

DELIMITERS = get_args(HexOutputDelimiter)
SAMPLES = [b"", b"\x00", b"A", bytes(range(256)), random.Random(7).randbytes(1000)]


def reference_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def reference_to_hex(data: bytes, name: str, per_line: int) -> str:
    if name == "0x with comma":
        pieces, delimiter = [f"0x{b:02x}" for b in data], ","
    elif name in {"0x", "\\x"}:
        pieces, delimiter = [f"{name}{b:02x}" for b in data], ""
    else:
        pieces, delimiter = [f"{b:02x}" for b in data], char_rep(name, " ")
    if not per_line:
        return delimiter.join(pieces)
    return "\n".join(
        delimiter.join(pieces[i : i + per_line]) for i in range(0, len(pieces), per_line)
    )


@pytest.mark.parametrize("key_length", [1, 2, 3, 7, 16, 1000])
def test_xor_matches_reference(key_length: int) -> None:
    rng = random.Random(key_length)
    key = rng.randbytes(key_length)
    for data in SAMPLES:
        expected = reference_xor(data, key)
        assert xor_repeating(data, key) == expected
        assert ctf.xor_bytes(data, key) == expected
        assert xor(data, key) == expected
        assert bake(data, [{"op": "XOR", "args": [{"string": key.hex(), "option": "Hex"}]}]) == (
            expected
        )


def test_xor_other_schemes_and_null_preserving_are_unchanged() -> None:
    data = b"\x00\x41\x42\x41"
    key = {"string": "41", "option": "Hex"}
    assert (
        xor(data, b"A", null_preserving=True) == b"\x00A\x03A"
    )  # bytes equal to the key or 0 are kept
    assert bake(data, [{"op": "XOR", "args": [key, "Cascade", False]}])  # still executes
    with pytest.raises(ValueError, match="empty"):
        xor_repeating(b"abc", b"")


@pytest.mark.parametrize("delimiter", DELIMITERS)
@pytest.mark.parametrize("per_line", [0, 1, 4, 16])
def test_to_hex_matches_reference_and_round_trips(delimiter: str, per_line: int) -> None:
    for data in SAMPLES:
        text = to_hex(data, delimiter=delimiter, bytes_per_line=per_line)  # type: ignore
        assert text == reference_to_hex(data, delimiter, per_line)
        assert from_hex(text) == data  # Auto detects every documented delimiter


def test_percent_delimiter_is_a_percent_sign() -> None:
    """Regression: 'Percent' used to be emitted literally ('41Percent42')."""
    assert to_hex(b"AB", delimiter="Percent") == "41%42"
    assert from_hex("41%42", delimiter="Percent") == b"AB"
    assert bake(b"AB", [{"op": "To Hex", "args": ["Percent", 0]}]) == "41%42"


def test_from_hex_auto_ignores_separators_and_prefixes() -> None:
    assert from_hex("0x41, 0x42;\\x43\n44") == b"ABCD"
    assert from_hex("") == b""
    assert from_hex("abc") == b"\x0a\xbc"  # odd digit count is left-padded
