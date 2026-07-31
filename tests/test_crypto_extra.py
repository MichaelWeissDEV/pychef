"""Official hash, KDF, OTP, and checksum vectors."""

from __future__ import annotations

import re

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("MD2", "1c8f1e6a94aaa7145210bf90bb52871a"),
        ("MD4", "94e3cb0fa9aa7a5ee3db74b79e915989"),
        ("SHA0", "5a5588f0407c6ae9a988758e76965f841b299229"),
    ],
)
def test_official_legacy_hash_vectors(operation: str, expected: str) -> None:
    assert bake("Hello, World!", [operation]) == expected


def test_additional_hash_vectors() -> None:
    assert bake("password", ["NT Hash"]) == "8846f7eaee8fb117ad06bdd830b7586c"
    assert bake("abc", ["SM3"]) == (
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    )
    assert bake("abc", [{"op": "RIPEMD", "args": ["160"]}]) == (
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    )


def test_official_pbkdf2_vector() -> None:
    args = [
        {"string": "Jack of All Trades Master of None", "option": "UTF8"},
        256,
        2,
        "MD5",
        {"string": "fruit", "option": "UTF8"},
    ]
    assert bake("", [{"op": "Derive PBKDF2 key", "args": args}]) == (
        "728a885b209e8b19cbd7430ca32608ff09190f7ccb7ded204e1d4c50f87c47bf"
    )


def test_hkdf_rfc5869_vector() -> None:
    args = [
        {"option": "Hex", "string": "000102030405060708090a0b0c"},
        {"option": "Hex", "string": "f0f1f2f3f4f5f6f7f8f9"},
        "SHA256",
        "with salt",
        42,
    ]
    assert bake(bytes.fromhex("0b" * 22), [{"op": "Derive HKDF key", "args": args}]) == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hotp_totp_and_validation() -> None:
    hotp = bake("JBSWY3DPEHPK3PXP", [{"op": "Generate HOTP", "args": ["Account", 6, 0]}])
    assert hotp == (
        "URI: otpauth://hotp/Account?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=0"
        "\n\nPassword: 282760"
    )
    totp = bake("JBSWY3DPEHPK3PXP", [{"op": "Generate TOTP", "args": ["Account", 6, 0, 30]}])
    assert isinstance(totp, str)
    assert re.fullmatch(r"URI: otpauth://totp/.+\n\nPassword: \d{6}", totp)
    with pytest.raises(OperationError, match="Name cannot be empty"):
        bake("JBSWY3DPEHPK3PXP", [{"op": "Generate HOTP", "args": ["", 6, 0]}])
    with pytest.raises(OperationError, match="less than or equal to 8"):
        bake("JBSWY3DPEHPK3PXP", [{"op": "Generate HOTP", "args": ["Account", 9, 0]}])


def test_luhn_official_vectors() -> None:
    assert bake("35641709012469", [{"op": "Luhn Checksum", "args": [10]}]) == (
        "Checksum: 7\nCheckdigit: 0\nLuhn Validated String: 356417090124690"
    )
    assert bake("", [{"op": "Luhn Checksum", "args": [10]}]) == ""
    with pytest.raises(OperationError, match="divisible by 2"):
        bake("123", [{"op": "Luhn Checksum", "args": [9]}])


def test_hash_analysis_and_extraction() -> None:
    analysis = bake("a" * 64, ["Analyse hash"])
    assert isinstance(analysis, str)
    assert "Bit length:  256" in analysis
    assert "SHA-256" in analysis
    source = f"before {'a' * 40} middle {'b' * 40} after"
    assert bake(source, [{"op": "Extract hashes", "args": [40, False, True]}]) == (
        f"Total found: 2\n\n{'a' * 40}\n{'b' * 40}"
    )
