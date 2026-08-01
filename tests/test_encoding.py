"""CyberChef-derived encoding compatibility vectors."""

from __future__ import annotations

import pytest

from pychef import bake
from pychef.errors import OperationError


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


def test_base85_official_variants_and_options() -> None:
    assert bake(b"hello world", [{"op": "To Base85", "args": ["!-u", False]}]) == ("BOu!rD]j7BEbo7")
    assert bake("BOu!rD]j7BEbo7\n", [{"op": "From Base85", "args": ["!-u", True, "z"]}]) == (
        b"hello world"
    )
    assert bake(b"\0" * 8, [{"op": "To Base85", "args": ["!-u", False]}]) == "zz"
    assert bake(b"\x86O\xd2o\xb5Y\xf7[", [{"op": "To Base85", "args": ["Z85", False]}]) == (
        "HelloWorld"
    )
    ipv6 = bytes.fromhex("108000000000000000080800200c417a")
    assert bake(ipv6, [{"op": "To Base85", "args": ["IPv6", False]}]) == ("5P$#x0000000;;GAPhlz")
    delimited = bake(b"test", [{"op": "To Base85", "args": ["!-u", True]}])
    assert isinstance(delimited, str)
    assert delimited.startswith("<~") and delimited.endswith("~>")
    assert bake(delimited, [{"op": "From Base85", "args": ["!-u", True, "z"]}]) == b"test"


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
    encoded = bake("A🐍", [{"op": "To Charcode", "args": ["Comma", 10]}])
    assert encoded == "65,128013"
    assert bake(encoded, [{"op": "From Charcode", "args": ["Comma", 10]}]) == "A🐍".encode()


def test_charcode_official_hex_vectors() -> None:
    plain = "ნუ პანიკას"
    encoded = "10dc 10e3 20 10de 10d0 10dc 10d8 10d9 10d0 10e1"
    assert bake(plain, [{"op": "To Charcode", "args": ["Space", 16]}]) == encoded
    assert bake(encoded, [{"op": "From Charcode", "args": ["Space", 16]}]) == plain.encode()
    all_bytes = "".join(map(chr, range(256)))
    assert bake(all_bytes, [{"op": "To Charcode", "args": ["Space", 16]}]) == " ".join(
        f"{ord(character):02x}" for character in all_bytes
    )


@pytest.mark.parametrize(
    ("plain", "args", "encoded"),
    [
        (
            "<a href='#'>\"&\"</a>",
            [False, "Named entities"],
            "&lt;a href&equals;&apos;&num;&apos;&gt;&quot;&amp;&quot;&lt;&sol;a&gt;",
        ),
        ("⇌ϵΩ█", [False, "Named entities"], "&rlhar;&epsiv;&#8486;&block;"),
        ("A<", [True, "Numeric entities"], "&#65;&#60;"),
        ("A<", [True, "Hex entities"], "&#x41;&#x3c;"),
    ],
)
def test_html_entity_official_encoding_vectors(
    plain: str, args: list[object], encoded: str
) -> None:
    assert bake(plain, [{"op": "To HTML Entity", "args": args}]) == encoded


def test_html_entity_official_decoding_vectors() -> None:
    assert bake("&ohm; &#65; &#x41; &notreal;", ["From HTML Entity"]) == "Ω A A &notreal;"


def test_url_html_quoted_printable_and_punycode() -> None:
    assert bake("a b/✓", [{"op": "URL Encode", "args": [False, True]}]) == "a%20b%2F%E2%9C%93"
    assert bake("a+b%2F", [{"op": "URL Decode", "args": [True]}]) == "a b/"
    assert bake("&lt;b&gt;", ["From HTML Entity"]) == "<b>"
    quoted = bake("Grüße", ["To Quoted Printable"])
    assert bake(quoted, ["From Quoted Printable"], return_type="str") == "Grüße"
    assert bake("münich.example", [{"op": "To Punycode", "args": [True]}]) == (
        "xn--mnich-kva.example"
    )
    assert bake("xn--mnich-kva.example", [{"op": "From Punycode", "args": [True]}]) == (
        "münich.example"
    )
    assert bake("münchen", ["To Punycode"]) == "mnchen-3ya"
    assert bake("mnchen-3ya", ["From Punycode"]) == "münchen"


def test_float_modhex_and_general_base_round_trips() -> None:
    packed = bake("1.5 -2", [{"op": "From Float", "args": ["Big endian", "Single precision"]}])
    assert (
        bake(packed, [{"op": "To Float", "args": ["Big endian", "Single precision"]}]) == "1.5 -2.0"
    )
    modhex = bake(b"\x01\xab", ["To Modhex"])
    assert bake(modhex, ["From Modhex"]) == b"\x01\xab"
    encoded = bake("256", [{"op": "To Base", "args": [16]}])
    assert encoded == "100"
    assert bake(encoded, [{"op": "From Base", "args": [16]}]) == "256"


@pytest.mark.parametrize(
    ("encoded", "radix", "decimal"),
    [
        ("1010", 2, "10"),
        ("10.1", 2, "2.5"),
        ("a.8", 16, "10.5"),
        ("77", 8, "63"),
        ("7.4", 8, "7.5"),
    ],
)
def test_from_base_official_vectors(encoded: str, radix: int, decimal: str) -> None:
    assert bake(encoded, [{"op": "From Base", "args": [radix]}]) == decimal
    assert bake(decimal, [{"op": "To Base", "args": [radix]}]) == encoded.lower()


@pytest.mark.parametrize(
    ("endianness", "size", "encoded"),
    [
        ("Big Endian", "Float (4 bytes)", "3f0000003f000000"),
        ("Little Endian", "Float (4 bytes)", "0000003f0000003f"),
        ("Big Endian", "Double (8 bytes)", "3fe00000000000003fe0000000000000"),
        ("Little Endian", "Double (8 bytes)", "000000000000e03f000000000000e03f"),
    ],
)
def test_float_official_vectors(endianness: str, size: str, encoded: str) -> None:
    data = bytes.fromhex(encoded)
    args = [endianness, size, "Comma"]
    assert bake(data, [{"op": "To Float", "args": args}]) == "0.5,0.5"
    assert bake("0.5,0.5", [{"op": "From Float", "args": args}]) == data


def test_to_float_rejects_incomplete_values() -> None:
    with pytest.raises(OperationError, match="multiple"):
        bake(b"\0\0\0", [{"op": "To Float", "args": ["Big Endian", "Float (4 bytes)"]}])
