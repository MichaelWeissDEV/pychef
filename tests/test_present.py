"""Official PRESENT block-cipher vectors ported from CyberChef."""

from __future__ import annotations

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("plaintext", "key", "expected"),
    [
        ("0000000000000000", "00000000000000000000", "5579c1387b228445"),
        ("0000000000000000", "ffffffffffffffffffff", "e72c46c0f5945049"),
        ("ffffffffffffffff", "00000000000000000000", "a112ffc72f68417b"),
        ("ffffffffffffffff", "ffffffffffffffffffff", "3333dcd3213210d2"),
        ("0000000000000000", "00000000000000000000000000000000", "96db702a2e6900af"),
        (
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
            "0e9d28685e671dd6",
        ),
    ],
)
def test_present_official_vectors(plaintext: str, key: str, expected: str) -> None:
    args = [
        {"string": key, "option": "Hex"},
        {"string": "", "option": "Hex"},
        "ECB",
        "Hex",
        "Hex",
        "NO",
    ]
    assert bake(plaintext, [{"op": "PRESENT Encrypt", "args": args}]) == expected
    assert bake(expected, [{"op": "PRESENT Decrypt", "args": args}]) == plaintext


def test_present_cbc_pkcs5_round_trip() -> None:
    encrypt_args = [
        {"string": "00112233445566778899", "option": "Hex"},
        {"string": "0102030405060708", "option": "Hex"},
        "CBC",
        "Raw",
        "Hex",
        "PKCS5",
    ]
    encrypted = bake("A longer PRESENT message", [{"op": "PRESENT Encrypt", "args": encrypt_args}])
    assert isinstance(encrypted, str)
    decrypt_args = [*encrypt_args[:3], "Hex", "Raw", "PKCS5"]
    assert bake(encrypted, [{"op": "PRESENT Decrypt", "args": decrypt_args}]) == (
        b"A longer PRESENT message"
    )
