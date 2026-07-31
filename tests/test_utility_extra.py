"""Tests for conversion, brute-force, checksum, and transition helpers."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


def test_unit_conversions() -> None:
    assert bake("1", [{"op": "Convert distance", "args": ["Miles (mi)", "Metres (m)"]}]) == (
        "1609.344"
    )
    assert bake("1", [{"op": "Convert area", "args": ["Hectare (ha)", "Square metre (sq m)"]}]) == (
        "10000"
    )
    assert bake("1", [{"op": "Convert mass", "args": ["Kilogram (kg)", "Gram (g)"]}]) == ("1000")
    assert (
        bake(
            "36",
            [
                {
                    "op": "Convert speed",
                    "args": ["Kilometres per hour (km/h)", "Metres per second (m/s)"],
                }
            ],
        )
        == "10.0008"
    )
    assert bake("1", [{"op": "Convert data units", "args": ["Kibibytes (KiB)", "Bytes (B)"]}]) == (
        "1024"
    )
    with pytest.raises(OperationError, match="invalid value or unit"):
        bake("1", [{"op": "Convert area", "args": ["unknown", "Square metre (sq m)"]}])


def test_convert_leet_official_vectors() -> None:
    assert bake("leet", [{"op": "Convert Leet Speak", "args": ["To Leet Speak"]}]) == "l337"
    assert bake("l337", [{"op": "Convert Leet Speak", "args": ["From Leet Speak"]}]) == "leet"
    assert bake("HELLO", [{"op": "Convert Leet Speak", "args": ["To Leet Speak"]}]) == "H3LL0"
    assert bake("H3LL0", [{"op": "Convert Leet Speak", "args": ["From Leet Speak"]}]) == "HeLLo"


def test_rot_brute_force_with_cribs() -> None:
    result = bake(
        "uryyb",
        [{"op": "ROT13 Brute Force", "args": [True, True, False, 100, 0, True, "hello"]}],
    )
    assert result == "Amount = 13: hello"
    result = bake("w6==@", [{"op": "ROT47 Brute Force", "args": [100, 0, True, "hello"]}])
    assert result == "Amount = 47: Hello"


def test_xor_brute_force_finds_single_byte_key() -> None:
    encrypted = bytes(byte ^ 0x2A for byte in b"known text")
    result = bake(
        encrypted,
        [{"op": "XOR Brute Force", "args": [1, 100, 0, "Standard", False, True, False, "known"]}],
    )
    assert "Key = 2a: known text" in result.splitlines()


def test_tcp_ip_checksum_vector() -> None:
    header = bytes.fromhex("450000730000400040110000c0a80001c0a800c7")
    assert bake(header, ["TCP/IP Checksum"]) == "b861"


def test_show_base64_offsets_escapes_custom_alphabet() -> None:
    result = bake(
        b"\x00\x10\x83\x10\x51\x87",
        [
            {
                "op": "Show Base64 offsets",
                "args": [
                    "<script>ale(1)/.ABCDEFGHIJKLMNOPQRSTUVWXYZbdfghjkmnoquvwxyz023456",
                    False,
                    "Raw",
                ],
            }
        ],
    )
    assert result == "&lt;script&gt;\n&lt;AQmsBRk66\n&lt;ia1AEIM6"


def test_ipv6_transition_official_vectors() -> None:
    expected = (
        "6to4: 2002:c633:6407::/48\nIPv4 Mapped: ::ffff:c633:6407\n"
        "IPv4 Translated: ::ffff:0:c633:6407\nNat 64: 64:ff9b::c633:6407\n"
    )
    assert (
        bake("198.51.100.7", [{"op": "IPv6 Transition Addresses", "args": [True, False]}])
        == expected
    )
    assert (
        bake("64:ff9b::c633:6407", [{"op": "IPv6 Transition Addresses", "args": [True, False]}])
        == "IPv4: 198.51.100.7\n"
    )
    assert (
        bake("a1:b2:c3:d4:e5:f6", [{"op": "IPv6 Transition Addresses", "args": [True, False]}])
        == "EUI-64 Interface ID: a3b2:c3ff:fed4:e5f6"
    )
    ranged = bake("198.51.100.0/24", [{"op": "IPv6 Transition Addresses", "args": [False, True]}])
    assert ranged == (
        "2002:c633:6400::/40\n::ffff:c633:6400/120\n"
        "::ffff:0:c633:6400/120\n64:ff9b::c633:6400/120\n"
    )
