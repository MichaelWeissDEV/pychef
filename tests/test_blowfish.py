"""Official CyberChef Blowfish mode and key-length vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_MESSAGE = "The quick brown fox jumps over the lazy dog."
_KEY = {"option": "Hex", "string": "0011223344556677"}
_ZERO_IV = {"option": "Hex", "string": "0000000000000000"}
_IV = {"option": "Hex", "string": "ffeeddccbbaa9988"}


@pytest.mark.parametrize(
    ("mode", "iv", "expected"),
    [
        (
            "ECB",
            _ZERO_IV,
            "f7784137ab1bf51546c0b120bdb7fed4509116e49283b35fab0e4292ac86251a"
            "9bf908330e3393815e3356bb26524027",
        ),
        (
            "CBC",
            _IV,
            "398433f39e938286a35fc240521435b6972f3fe96846b54ab9351aa5fa9e10a6"
            "a94074e883d1cb36cb9657c817274b60",
        ),
        (
            "CFB",
            _IV,
            "c8ca123592570c1fcb138d4ec08f7af14ad49363245be1ac25029c8ffc508b32"
            "17e75faaa5566426180fec8f",
        ),
        (
            "OFB",
            _IV,
            "c8ca123592570c1fffcee88b9823b9450dc9c48e559123c1df1984214212bae7"
            "e44114d29dba79683d10cce5",
        ),
        (
            "CTR",
            _ZERO_IV,
            "e2a5e0f03ad4877101c7cf83861ad93477adb57acac4bebc315a7bae34b4e6a5"
            "4e5532db457a3131dcd9dda6",
        ),
    ],
)
def test_blowfish_official_mode_vectors(mode: str, iv: dict[str, str], expected: str) -> None:
    encrypt_args = [_KEY, iv, mode, "Raw", "Hex"]
    decrypt_args = [_KEY, iv, mode, "Hex", "Raw"]
    assert bake(_MESSAGE, [{"op": "Blowfish Encrypt", "args": encrypt_args}]) == expected
    assert bake(expected, [{"op": "Blowfish Decrypt", "args": decrypt_args}]) == _MESSAGE.encode()


def test_blowfish_official_binary_vector() -> None:
    plaintext = (
        "7a0e643132750e96d805d11e9e48e281fa39a41039286423cc1c045e5442b40b"
        "f1c3f2822bded3f9c8ef11cb25da64dda9c7ab87c246bd305385150c98f31465"
        "c2a6180fe81d31ea289b916504d5a12e1de26cb10adba84a0cb0c86f94bc14bc"
        "554f3018"
    )
    expected = (
        "3b42c51465896524e66c2fd2404c8c2b4eb26c760671f131c3372d374f48283c"
        "a9a5404d3d8aabd2a886c6551393ca41c682580f1c81f16046e3bec7b59247bd"
        "fca1d40bf2ad8ede9de99cb44b36658f775999d37776b3b1a085b9530e54ece6"
        "9e1875e1bdc8cdcf"
    )
    args = [_KEY, _IV, "CBC", "Hex", "Hex"]
    assert bake(plaintext, [{"op": "Blowfish Encrypt", "args": args}]) == expected
    assert bake(expected, [{"op": "Blowfish Decrypt", "args": args}]) == plaintext


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (
            "00112233",
            "823f337a53ecf121aa9ec1b111bd5064d1d7586abbdaaa0c8fd0c6cc43c831c8"
            "8bf088ee3e07287e3f36cf2e45f9c7e6",
        ),
        (
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
            "19f5a68145b34321cfba72226b0f33922ce44dd6e7869fe328db64faae156471"
            "216f12ed2a37fd0bdd7cebf867b3cff0",
        ),
    ],
)
def test_blowfish_official_variable_key_vectors(key: str, expected: str) -> None:
    args = [{"option": "Hex", "string": key}, _ZERO_IV, "CBC", "Raw", "Hex"]
    assert bake(_MESSAGE, [{"op": "Blowfish Encrypt", "args": args}]) == expected


def test_blowfish_toggle_formats_raw_output_and_validation() -> None:
    args = [
        {"option": "UTF8", "string": "four-byte key"},
        {"option": "Base64", "string": "MTIzNDU2Nzg="},
        "OFB",
        "Raw",
        "Raw",
    ]
    encrypted = bake("raw Blowfish", [{"op": "Blowfish Encrypt", "args": args}])
    assert isinstance(encrypted, bytes)
    assert bake(encrypted, [{"op": "Blowfish Decrypt", "args": args}]) == b"raw Blowfish"

    with pytest.raises(OperationError, match="between 4 and 56"):
        bake("", [{"op": "Blowfish Encrypt", "args": [{"option": "Hex", "string": "000102"}]}])
    with pytest.raises(OperationError, match="Invalid IV length: 0"):
        bake(
            "",
            [
                {
                    "op": "Blowfish Encrypt",
                    "args": [
                        {"option": "Hex", "string": "00010203"},
                        {"option": "Hex", "string": ""},
                    ],
                }
            ],
        )
    with pytest.raises(OperationError, match="Unable to decrypt"):
        bake(
            "0000000000000000",
            [{"op": "Blowfish Decrypt", "args": [_KEY, _ZERO_IV, "CBC", "Hex", "Raw"]}],
        )
