"""NIST CMAC vectors translated from CyberChef's upstream tests."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_MESSAGES_AES = [
    "",
    "6bc1bee22e409f96e93d7e117393172a",
    "6bc1bee22e409f96e93d7e117393172aae2d8a57",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
]
_MESSAGES_TDES = [*_MESSAGES_AES[:3], _MESSAGES_AES[3][:64]]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            [
                "bb1d6929e95937287fa37d129b756746",
                "070a16b46b4d4144f79bdd9dd04a287c",
                "7d85449ea6ea19c823a7bf78837dfade",
                "51f0bebf7e3b9d92fc49741779363cfe",
            ],
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            [
                "d17ddf46adaacde531cac483de7a9367",
                "9e99a7bf31e710900662f65e617c5184",
                "3d75c194ed96070444a9fa7ec740ecf8",
                "a1d5df0eed790f794d77589659f39a11",
            ],
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            [
                "028962f61b7bf89efc6b551f4667d983",
                "28a7023f452e8f82bd4bf28d8c37c35c",
                "156727dc0878944a023c1fe03bad6d93",
                "e1992190549f6ed5696a2c056c315410",
            ],
        ),
    ],
)
def test_cmac_aes_nist_vectors(key: str, expected: list[str]) -> None:
    args = [{"option": "Hex", "string": key}, "AES"]
    assert [
        bake(bytes.fromhex(message), [{"op": "CMAC", "args": args}]) for message in _MESSAGES_AES
    ] == expected


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (
            "0123456789abcdef23456789abcdef01456789abcdef0123",
            [
                "7db0d37df936c550",
                "30239cf1f52e6609",
                "6c9f3ee4923f6be2",
                "99429bd0bf7904e5",
            ],
        ),
        (
            "0123456789abcdef23456789abcdef010123456789abcdef",
            [
                "79ce52a7f786a960",
                "cc18a0b79af2413b",
                "c06d377ecd101969",
                "9cd33580f9b64dfb",
            ],
        ),
    ],
)
def test_cmac_triple_des_nist_vectors(key: str, expected: list[str]) -> None:
    args = [{"option": "Hex", "string": key}, "Triple DES"]
    assert [
        bake(bytes.fromhex(message), [{"op": "CMAC", "args": args}]) for message in _MESSAGES_TDES
    ] == expected


def test_cmac_validates_algorithm_and_key_lengths() -> None:
    invalid_key = {"option": "Hex", "string": "00" * 20}
    with pytest.raises(OperationError, match="key for AES"):
        bake(b"", [{"op": "CMAC", "args": [invalid_key, "AES"]}])
    with pytest.raises(OperationError, match="key for Triple DES"):
        bake(b"", [{"op": "CMAC", "args": [invalid_key, "Triple DES"]}])
    with pytest.raises(OperationError, match="Undefined"):
        bake(b"", [{"op": "CMAC", "args": [invalid_key, "unknown"]}])
