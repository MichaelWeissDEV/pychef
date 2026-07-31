"""NIST and official CyberChef vectors for the Ascon operation family."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_KEY = "000102030405060708090a0b0c0d0e0f"
_NONCE = "101112131415161718191a1b1c1d1e1f"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (b"P", "b96da347d720272533a87f5a94a356155f49cdf7c0c10a3e6f346d8a2293e480"),
        (b"", "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2"),
        (b"Hello", "c1beebe1251d562c4526d6b947cefb932998499424f6cd186e764aa0a36cddb7"),
        (
            b"Hello, World!",
            "f40e1ce8d4272e628e9535193f196f4ff2a720b00f6380c5d6f16b975f3a7777",
        ),
    ],
)
def test_ascon_hash_official_vectors(message: bytes, expected: str) -> None:
    assert bake(message, [{"op": "Ascon Hash", "args": []}]) == expected


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (b"", "eac9d74bbedf8bf1eba2862b26aa6d39"),
        (b"\x10", "e5be5b6dfb7b0e3eae00a070791947a8"),
        (b"\x10\x11\x12\x13", "727f6386405a52ad7ca0669a6a885294"),
    ],
)
def test_ascon_mac_official_vectors(message: bytes, expected: str) -> None:
    args = [{"option": "Hex", "string": _KEY}]
    assert bake(message, [{"op": "Ascon MAC", "args": args}]) == expected


def test_ascon_mac_toggle_formats_and_key_validation() -> None:
    assert (
        bake(
            b"",
            [
                {
                    "op": "Ascon MAC",
                    "args": [{"option": "Base64", "string": "AAECAwQFBgcICQoLDA0ODw=="}],
                }
            ],
        )
        == "eac9d74bbedf8bf1eba2862b26aa6d39"
    )
    with pytest.raises(OperationError, match="Invalid key length: 8 bytes"):
        bake(b"test", [{"op": "Ascon MAC", "args": [{"option": "Hex", "string": "00" * 8}]}])


@pytest.mark.parametrize(
    ("plaintext", "associated_data", "expected"),
    [
        (b"", "", "4f9c278211bec9316bf68f46ee8b2ec6"),
        (b"", "30", "cccb674fe18a09a285d6ab11b35675c0"),
        (b"\x20", "", "e8dd576aba1cd3e6fc704de02aedb79588"),
        (
            bytes.fromhex("20212223242526272829"),
            "30313233343536373839",
            "12042996da42b4536e5a0e64692cf6041ff8c367e1423253c84c",
        ),
        (
            bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
            "303132333435363738393a3b3c3d3e3f",
            "6373ebb28be97c9bac090cf399c13ef13abfc0d209e8f4844c90814d13f32c59",
        ),
    ],
)
def test_ascon_aead_official_nist_vectors(
    plaintext: bytes,
    associated_data: str,
    expected: str,
) -> None:
    args = [
        {"option": "Hex", "string": _KEY},
        {"option": "Hex", "string": _NONCE},
        {"option": "Hex", "string": associated_data},
        "Raw",
        "Hex",
    ]
    assert bake(plaintext, [{"op": "Ascon Encrypt", "args": args}]) == expected
    decrypt_args = [*args[:3], "Hex", "Raw"]
    assert bake(expected, [{"op": "Ascon Decrypt", "args": decrypt_args}]) == plaintext


@pytest.mark.parametrize(
    ("plaintext", "key", "nonce", "associated_data", "expected"),
    [
        (b"Hello", _KEY, _KEY, "", "af14bce6b9b6588c3aa63f9ddc5a0cf5f565f358b0"),
        (b"Hello", _KEY, _KEY, "6d65746164617461", "351880c09f9dee12c20c4ba973066bc10dd26000b6"),
        (
            b"test message",
            _KEY,
            _KEY,
            "",
            "9314a3fef6cc299a07b8c9e0f9e479ca0d1187e87345cf590adc572b",
        ),
        (b"", _KEY, _KEY, "", "4427d64b8e1e1451fc445960f0839bb0"),
        (b"Hello", "00" * 16, "00" * 16, "", "403281e117ebb087e2d9196552b2d123bccb7b5500"),
    ],
)
def test_ascon_aead_official_cyberchef_vectors(
    plaintext: bytes,
    key: str,
    nonce: str,
    associated_data: str,
    expected: str,
) -> None:
    encrypt_args = [
        {"option": "Hex", "string": key},
        {"option": "Hex", "string": nonce},
        {"option": "Hex", "string": associated_data},
        "Raw",
        "Hex",
    ]
    decrypt_args = [*encrypt_args[:3], "Hex", "Raw"]
    assert bake(plaintext, [{"op": "Ascon Encrypt", "args": encrypt_args}]) == expected
    assert bake(expected, [{"op": "Ascon Decrypt", "args": decrypt_args}]) == plaintext


def test_ascon_aead_authentication_and_length_validation() -> None:
    valid = {"option": "Hex", "string": _KEY}
    empty = {"option": "Hex", "string": ""}
    with pytest.raises(OperationError, match="Invalid key length: 0 bytes"):
        bake(b"test", [{"op": "Ascon Encrypt", "args": [empty, valid, empty]}])
    with pytest.raises(OperationError, match="Invalid nonce length: 0 bytes"):
        bake(b"test", [{"op": "Ascon Encrypt", "args": [valid, empty, empty]}])
    with pytest.raises(OperationError, match="authentication failed"):
        bake(
            "bf14bce6b9b6588c3aa63f9ddc5a0cf5f565f358b0",
            [{"op": "Ascon Decrypt", "args": [valid, valid, empty, "Hex", "Raw"]}],
        )
    with pytest.raises(OperationError, match="authentication failed"):
        bake(
            "af14bce6b9b6588c3aa63f9ddc5a0cf5f565f358b0",
            [
                {
                    "op": "Ascon Decrypt",
                    "args": [
                        valid,
                        valid,
                        {"option": "UTF8", "string": "wrong data"},
                        "Hex",
                        "Raw",
                    ],
                }
            ],
        )


def test_ascon_aead_all_toggle_and_io_formats() -> None:
    args = [
        {"option": "UTF8", "string": "0123456789abcdef"},
        {"option": "Latin1", "string": "fedcba9876543210"},
        {"option": "Base64", "string": "bWV0YWRhdGE="},
        "Hex",
        "Raw",
    ]
    encrypted = bake("000102ff", [{"op": "Ascon Encrypt", "args": args}])
    assert isinstance(encrypted, bytes)
    decrypt_args = [*args[:3], "Raw", "Hex"]
    assert bake(encrypted, [{"op": "Ascon Decrypt", "args": decrypt_args}]) == "000102ff"
