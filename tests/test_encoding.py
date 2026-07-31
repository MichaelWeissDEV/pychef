"""CyberChef-derived encoding compatibility vectors."""

from __future__ import annotations

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("plain", "encoded"),
    [
        ("", ""),
        ("Hello, World!", "SGVsbG8sIFdvcmxkIQ=="),
        ("ნუ პანიკას", "4YOc4YOjIOGDnuGDkOGDnOGDmOGDmeGDkOGDoQ=="),
    ],
)
def test_base64_official_vectors(plain: str, encoded: str) -> None:
    assert bake(plain, [{"op": "To Base64", "args": ["A-Za-z0-9+/="]}]) == encoded
    assert (
        bake(
            encoded,
            [{"op": "From Base64", "args": ["A-Za-z0-9+/=", True]}],
            return_type="str",
        )
        == plain
    )


def test_base64_custom_and_url_safe_alphabets() -> None:
    assert bake(b"\xfb\xff", [{"op": "To Base64", "args": ["A-Za-z0-9-_"]}]) == "-_8"
    assert bake("-_8", [{"op": "From Base64", "args": ["A-Za-z0-9-_", True]}]) == b"\xfb\xff"


@pytest.mark.parametrize("operation", ["Base32", "Base58", "Base62", "Base85"])
def test_base_round_trips(operation: str) -> None:
    encoded = bake(b"\0Hello world", [{"op": f"To {operation}", "args": []}])
    assert bake(encoded, [{"op": f"From {operation}", "args": []}]) == b"\0Hello world"


@pytest.mark.parametrize(
    ("delimiter", "expected"),
    [
        ("Space", "48 69"),
        ("None", "4869"),
        ("0x", "0x480x69"),
        ("0x with comma", "0x48,0x69"),
        ("\\x", "\\x48\\x69"),
    ],
)
def test_hex_delimiters(delimiter: str, expected: str) -> None:
    assert bake("Hi", [{"op": "To Hex", "args": [delimiter, 0]}]) == expected
    assert bake(expected, [{"op": "From Hex", "args": [delimiter]}]) == b"Hi"


@pytest.mark.parametrize(
    ("encoder", "decoder", "encoded"),
    [
        ("To Binary", "From Binary", "01001000 01101001"),
        ("To Octal", "From Octal", "110 151"),
        ("To Decimal", "From Decimal", "72 105"),
    ],
)
def test_numeric_byte_representations(encoder: str, decoder: str, encoded: str) -> None:
    assert bake("Hi", [{"op": encoder, "args": ["Space"]}]) == encoded
    assert bake(encoded, [{"op": decoder, "args": ["Space"]}]) == b"Hi"


def test_charcode_unicode_round_trip() -> None:
    encoded = bake("A🐍", [{"op": "To Charcode", "args": [10, "Comma"]}])
    assert encoded == "65,128013"
    assert bake(encoded, [{"op": "From Charcode", "args": [10, "Comma"]}]) == "A🐍"


def test_url_html_quoted_printable_and_punycode() -> None:
    assert bake("a b/✓", [{"op": "URL Encode", "args": [False, True]}]) == "a%20b%2F%E2%9C%93"
    assert bake("a+b%2F", [{"op": "URL Decode", "args": [True]}]) == "a b/"
    assert bake("&lt;b&gt;", ["From HTML Entity"]) == "<b>"
    quoted = bake("Grüße", ["To Quoted Printable"])
    assert bake(quoted, ["From Quoted Printable"], return_type="str") == "Grüße"
    assert bake("münich.example", ["To Punycode"]) == "xn--mnich-kva.example"
    assert bake("xn--mnich-kva.example", ["From Punycode"]) == "münich.example"


def test_float_modhex_and_general_base_round_trips() -> None:
    packed = bake("1.5 -2", [{"op": "From Float", "args": ["Big endian", "Single precision"]}])
    assert (
        bake(packed, [{"op": "To Float", "args": ["Big endian", "Single precision"]}]) == "1.5 -2.0"
    )
    modhex = bake(b"\x01\xab", ["To Modhex"])
    assert bake(modhex, ["From Modhex"]) == b"\x01\xab"
    encoded = bake(b"\x01\x00", [{"op": "To Base", "args": [16]}])
    assert encoded == "100"
    assert bake(encoded, [{"op": "From Base", "args": [16]}]) == b"\x01\x00"
