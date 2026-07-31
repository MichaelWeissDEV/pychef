"""Official vectors for dependency-free modern cipher ports."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


def _tea_args(key: str, *, mode: str = "ECB", padding: str = "NO") -> list[object]:
    return [
        {"option": "Hex", "string": key},
        {"option": "Hex", "string": ""},
        mode,
        "Hex",
        "Hex",
        padding,
    ]


def test_tea_official_zero_vector() -> None:
    args = _tea_args("00" * 16)
    assert bake("00" * 8, [{"op": "TEA Encrypt", "args": args}]) == "41ea3a0a94baa940"
    assert bake("41ea3a0a94baa940", [{"op": "TEA Decrypt", "args": args}]) == "00" * 8


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("4142434445464748", "497df3d072612cb5"),
        ("4141414141414141", "e78f2d13744341d8"),
    ],
)
def test_xtea_official_vectors(source: str, expected: str) -> None:
    args = [*_tea_args("000102030405060708090a0b0c0d0e0f"), 32]
    assert bake(source, [{"op": "XTEA Encrypt", "args": args}]) == expected
    assert bake(expected, [{"op": "XTEA Decrypt", "args": args}]) == source


@pytest.mark.parametrize("mode", ["CBC", "CFB", "OFB", "CTR"])
def test_tea_modes_round_trip(mode: str) -> None:
    key = {"option": "Hex", "string": "0123456789abcdef0123456789abcdef"}
    iv = {"option": "Hex", "string": "aabbccddeeff0011"}
    padding = "PKCS5" if mode == "CBC" else "NO"
    encrypt_args = [key, iv, mode, "Raw", "Hex", padding]
    decrypt_args = [key, iv, mode, "Hex", "Raw", padding]
    encrypted = bake("mode test", [{"op": "TEA Encrypt", "args": encrypt_args}])
    assert bake(encrypted, [{"op": "TEA Decrypt", "args": decrypt_args}]) == b"mode test"


def test_xxtea_official_vector_and_round_trip() -> None:
    key = [{"option": "UTF8", "string": "1234567890"}]
    encrypted = bake("ნუ პანიკას", [{"op": "XXTEA Encrypt", "args": key}])
    assert isinstance(encrypted, bytes)
    assert encrypted.hex() == "3db5a39db1663fc029bb630a38635b8de5bfef62192e52cc4bf83cda8ccbc701"
    assert bake(encrypted, [{"op": "XXTEA Decrypt", "args": key}]) == "ნუ პანიკას".encode()


def test_ciphersaber_official_decrypt_and_round_trip() -> None:
    ciphertext = bytes.fromhex(
        "6f6d0babf3aa6719031530edb677ca74e0089dd0e7b8854356bb1448e37cdbefe7f3a84f4f5fb3fd"
    )
    args = [{"option": "Latin1", "string": "asdfg"}, 1]
    assert bake(ciphertext, [{"op": "CipherSaber2 Decrypt", "args": args}]) == (
        b"This is a test of CipherSaber."
    )
    encrypted = bake("Hello World", [{"op": "CipherSaber2 Encrypt", "args": args}])
    assert isinstance(encrypted, bytes)
    assert len(encrypted) == 21
    assert bake(encrypted, [{"op": "CipherSaber2 Decrypt", "args": args}]) == b"Hello World"


def test_rc4_drop_official_vector_and_validation() -> None:
    args = [
        {"string": "Under Your Nose", "option": "UTF8"},
        "UTF8",
        "Hex",
        192,
    ]
    assert bake("Go Out On a Limb", [{"op": "RC4 Drop", "args": args}]) == (
        "b85cb1c4ed6bed8f260ab92829bba942"
    )
    with pytest.raises(OperationError, match="key must not be empty"):
        bake("x", [{"op": "RC4 Drop", "args": [{"string": "", "option": "UTF8"}]}])
