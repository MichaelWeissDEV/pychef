"""Official IETF RC6 vectors ported from CyberChef."""

from __future__ import annotations

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("word_size", "rounds", "key", "plaintext", "ciphertext"),
    [
        (8, 12, "00010203", "00010203", "aefc4612"),
        (16, 16, "0001020304050607", "0001020304050607", "2ff0b68eaeffad5b"),
        (
            32,
            20,
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "3a96f9c7f6755cfe46f00e3dcd5d2a3c",
        ),
        (
            64,
            24,
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "c002de050bd55e5d36864ab9853338e6dc4a1326c6bdaaeb1bc9e4fd67886617",
        ),
        (24, 4, "", "000102030405060708090a0b", "0177982579be2ee3303269b9"),
        (
            80,
            4,
            "000102030405060708090a0b",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
            "26d9d6128601d06dec3817d401f1c0ff715473543875da417c2116d1e87c919a49311b00b4e17962",
        ),
    ],
)
def test_rc6_ietf_vectors(
    word_size: int, rounds: int, key: str, plaintext: str, ciphertext: str
) -> None:
    args = [
        {"string": key, "option": "Hex"},
        {"string": "", "option": "Hex"},
        "ECB",
        "Hex",
        "Hex",
        "NO",
        word_size,
        rounds,
    ]
    assert bake(plaintext, [{"op": "RC6 Encrypt", "args": args}]) == ciphertext
    assert bake(ciphertext, [{"op": "RC6 Decrypt", "args": args}]) == plaintext


@pytest.mark.parametrize("mode", ["CBC", "CFB", "OFB", "CTR", "ECB"])
def test_rc6_modes_round_trip(mode: str) -> None:
    iv = "00112233445566778899aabbccddeeff" if mode != "ECB" else ""
    encrypt_args = [
        {"string": "00112233445566778899aabbccddeeff", "option": "Hex"},
        {"string": iv, "option": "Hex"},
        mode,
        "Raw",
        "Hex",
        "PKCS5",
        32,
        20,
    ]
    ciphertext = bake("RC6 mode test message", [{"op": "RC6 Encrypt", "args": encrypt_args}])
    assert isinstance(ciphertext, str)
    decrypt_args = [*encrypt_args[:3], "Hex", "Raw", *encrypt_args[5:]]
    assert bake(ciphertext, [{"op": "RC6 Decrypt", "args": decrypt_args}]) == (
        b"RC6 mode test message"
    )
