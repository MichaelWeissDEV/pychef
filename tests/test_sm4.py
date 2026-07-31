"""IETF SM4 vectors translated from CyberChef's upstream tests."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_TWO_BLOCKS = (
    "aa aa aa aa bb bb bb bb cc cc cc cc dd dd dd dd "
    "ee ee ee ee ff ff ff ff aa aa aa aa bb bb bb bb"
)
_FOUR_BLOCKS = (
    "aa aa aa aa aa aa aa aa bb bb bb bb bb bb bb bb "
    "cc cc cc cc cc cc cc cc dd dd dd dd dd dd dd dd "
    "ee ee ee ee ee ee ee ee ff ff ff ff ff ff ff ff "
    "aa aa aa aa aa aa aa aa bb bb bb bb bb bb bb bb"
)
_KEY_1 = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
_KEY_2 = "fe dc ba 98 76 54 32 10 01 23 45 67 89 ab cd ef"
_IV = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"


@pytest.mark.parametrize(
    ("key", "mode", "plaintext", "ciphertext"),
    [
        (
            _KEY_1,
            "ECB/NoPadding",
            _TWO_BLOCKS,
            "5e c8 14 3d e5 09 cf f7 b5 17 9f 8f 47 4b 86 19 "
            "2f 1d 30 5a 7f b1 7d f9 85 f8 1c 84 82 19 23 04",
        ),
        (
            _KEY_2,
            "ECB/NoPadding",
            _TWO_BLOCKS,
            "c5 87 68 97 e4 a5 9b bb a7 2a 10 c8 38 72 24 5b "
            "12 dd 90 bc 2d 20 06 92 b5 29 a4 15 5a c9 e6 00",
        ),
        (
            _KEY_1,
            "CBC/NoPadding",
            _TWO_BLOCKS,
            "78 eb b1 1c c4 0b 0a 48 31 2a ae b2 04 02 44 cb "
            "4c b7 01 69 51 90 92 26 97 9b 0d 15 dc 6a 8f 6d",
        ),
        (
            _KEY_2,
            "CBC/NoPadding",
            _TWO_BLOCKS,
            "0d 3a 6d dc 2d 21 c6 98 85 72 15 58 7b 7b b5 9a "
            "91 f2 c1 47 91 1a 41 44 66 5e 1f a1 d4 0b ae 38",
        ),
        (
            _KEY_1,
            "OFB",
            _TWO_BLOCKS,
            "ac 32 36 cb 86 1d d3 16 e6 41 3b 4e 3c 75 24 b7 "
            "1d 01 ac a2 48 7c a5 82 cb f5 46 3e 66 98 53 9b",
        ),
        (
            _KEY_1,
            "CFB",
            _TWO_BLOCKS,
            "ac 32 36 cb 86 1d d3 16 e6 41 3b 4e 3c 75 24 b7 "
            "69 d4 c5 4e d4 33 b9 a0 34 60 09 be b3 7b 2b 3f",
        ),
        (
            _KEY_1,
            "CTR",
            _FOUR_BLOCKS,
            "ac 32 36 cb 97 0c c2 07 91 36 4c 39 5a 13 42 d1 "
            "a3 cb c1 87 8c 6f 30 cd 07 4c ce 38 5c dd 70 c7 "
            "f2 34 bc 0e 24 c1 19 80 fd 12 86 31 0c e3 7b 92 "
            "6e 02 fc d0 fa a0 ba f3 8b 29 33 85 1d 82 45 14",
        ),
        (
            _KEY_2,
            "CTR",
            _FOUR_BLOCKS,
            "5d cc cd 25 b9 5a b0 74 17 a0 85 12 ee 16 0e 2f "
            "8f 66 15 21 cb ba b4 4c c8 71 38 44 5b c2 9e 5c "
            "0a e0 29 72 05 d6 27 04 17 3b 21 23 9b 88 7f 6c "
            "8c b5 b8 00 91 7a 24 88 28 4b de 9e 16 ea 29 06",
        ),
    ],
)
def test_sm4_official_mode_vectors(key: str, mode: str, plaintext: str, ciphertext: str) -> None:
    iv = "" if mode.startswith("ECB") else _IV
    args = [
        {"option": "Hex", "string": key},
        {"option": "Hex", "string": iv},
        mode,
        "Hex",
        "Hex",
    ]
    assert bake(plaintext, [{"op": "SM4 Encrypt", "args": args}]) == ciphertext
    assert bake(ciphertext, [{"op": "SM4 Decrypt", "args": args}]) == plaintext


def test_sm4_official_pkcs7_vector_and_raw_round_trip() -> None:
    args = [
        {"option": "Hex", "string": _KEY_1},
        {"option": "Hex", "string": ""},
        "ECB",
        "Hex",
        "Hex",
    ]
    expected = (
        "5e c8 14 3d e5 09 cf f7 b5 17 9f 8f 47 4b 86 19 "
        "2f 1d 30 5a 7f b1 7d f9 85 f8 1c 84 82 19 23 04 "
        "00 2a 8a 4e fa 86 3c ca d0 24 ac 03 00 bb 40 d2"
    )
    assert bake(_TWO_BLOCKS, [{"op": "SM4 Encrypt", "args": args}]) == expected
    assert bake(expected, [{"op": "SM4 Decrypt", "args": args}]) == _TWO_BLOCKS

    raw_args = [args[0], {"option": "Hex", "string": _IV}, "CTR", "Raw", "Raw"]
    encrypted = bake("partial SM4 stream", [{"op": "SM4 Encrypt", "args": raw_args}])
    assert isinstance(encrypted, bytes)
    assert bake(encrypted, [{"op": "SM4 Decrypt", "args": raw_args}]) == b"partial SM4 stream"


def test_sm4_validates_key_iv_and_no_padding() -> None:
    with pytest.raises(OperationError, match="Invalid key length"):
        bake("", [{"op": "SM4 Encrypt", "args": []}])
    key = {"option": "Hex", "string": _KEY_1}
    with pytest.raises(OperationError, match="Invalid IV length"):
        bake("data", [{"op": "SM4 Encrypt", "args": [key]}])
    with pytest.raises(OperationError, match="16-byte multiple"):
        bake(
            "short",
            [
                {
                    "op": "SM4 Encrypt",
                    "args": [key, {"option": "Hex", "string": ""}, "ECB/NoPadding"],
                }
            ],
        )
