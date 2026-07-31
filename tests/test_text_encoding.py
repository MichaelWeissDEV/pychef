"""Official CyberChef character encoding vectors."""

from __future__ import annotations

from pychef import bake


def test_encode_decode_text_official_vectors() -> None:
    recipe = [
        {"op": "Encode text", "args": ["UTF-8 (65001)"]},
        {"op": "Decode text", "args": ["UTF-8 (65001)"]},
    ]
    assert bake("", recipe) == ""
    assert bake("hello", recipe) == "hello"
    encoded = bake("hello", [{"op": "Encode text", "args": ["IBM EBCDIC International (500)"]}])
    assert encoded == bytes.fromhex("88 85 93 93 96")
    assert (
        bake(encoded, [{"op": "Decode text", "args": ["IBM EBCDIC International (500)"]}])
        == "hello"
    )


def test_text_encoding_special_cases() -> None:
    assert bake("hello", [{"op": "Encode text", "args": [""]}]) == ("Encoding cannot be empty.")
    assert bake(b"hello", [{"op": "Decode text", "args": [""]}]) == ("Encoding cannot be empty.")
    powershell = bytes.fromhex("6400690072002000220063003a005c00700072006f006700720061006d002000")
    assert bake(powershell, [{"op": "Decode text", "args": ["UTF-16LE (1200)"]}]) == (
        'dir "c:\\program '
    )
