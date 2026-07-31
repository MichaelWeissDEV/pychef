"""CyberChef and standards vectors for DES, Triple DES, and LM hashing."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_INPUT = (
    "7a0e643132750e96d805d11e9e48e281fa39a41039286423cc1c045e5442b40b"
    "f1c3f2822bded3f9c8ef11cb25da64dda9c7ab87c246bd305385150c98f31465"
    "c2a6180fe81d31ea289b916504d5a12e1de26cb10adba84a0cb0c86f94bc14bc"
    "554f3018"
)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (
            "CBC",
            "6500defb824b0eb8ccbf1fa9689c6f5bcc65247d93ecb0e573232824bca82dd4"
            "1e2361f8fd82ef187de9f3b74f7ba3ca2b4e735f3ca6304fb8dd1675933c5764"
            "24b1ea72b3219bdab62fce56d49c820d5ac02a4702a6d688e90b0933de97da21"
            "e4829e5cf85caae8",
        ),
        (
            "CFB",
            "09015087e15b09374bc9edba80ce41e6809e332fc1e988858749fb2f4ebbd648"
            "3a6fce01a43271280c07c90e13d517729acac45beef7d088339eb7e084bbbb74"
            "59fc8bb592d2ca76b90066dc79b1fbc5e016208e1d02c6e48ab675530f8040e5"
            "3e1a138b",
        ),
        (
            "OFB",
            "09015087e15b09374d8879bac14dbad851dd08fb131353a8c510acc4570e97720"
            "dd159465f1c7da3cac4a50521e1c1ab87e8cf5b0aa0c1d2eaa8a1ed914a26c1"
            "3b2b0a76a368f08812fc7fa4b7c047f27df0c35e5f53b8a20e2ffc10e55d388"
            "cae8070db",
        ),
        (
            "CTR",
            "09015087e15b0937c462fd5974af0c4b5880de136a5680453c99f4500628cbec"
            "a769623515d836985110b93eacfea7fa4a7b2b3cb4f67acbb5f7e8ddb5a5d445"
            "da74bf6572b0a874befa3888c81110776388e400afd8dc908dcc0c018c7753355"
            "f8a1c9f",
        ),
        (
            "ECB",
            "8dea4c6a35d5f6a419232159a0b039798d0a0b20fd1e559b1d04f8eb1120e8bc"
            "a6ed5b3a4bc2b23d3b62312e6085d9e837677569fe79a65eba7cb4a2969e099f"
            "c1bd649e9c8aeb2c4c519e085db6974819257c20fde70acabc976308cc4163503"
            "8c91acf5eefff1e",
        ),
    ],
)
def test_des_official_mode_vectors(mode: str, expected: str) -> None:
    iv = "533ed1378bfd929e" if mode != "ECB" else ""
    encrypt_args = [
        {"option": "Hex", "string": "58345efb0a64e87e"},
        {"option": "Hex", "string": iv},
        mode,
        "Hex",
        "Hex",
    ]
    assert bake(_INPUT, [{"op": "DES Encrypt", "args": encrypt_args}]) == expected
    decrypt_args = [*encrypt_args[:3], "Hex", "Hex"]
    assert bake(expected, [{"op": "DES Decrypt", "args": decrypt_args}]) == _INPUT


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (
            "CBC",
            "f826c9116ea932eb7027a810b5ce21109c4ef2563c9f3ba5e2518f72484e88f8"
            "d3f6ff3f334f64bb6bb9ff91b70f6f29c037b10dee5fe16d7f0f41c9a7ecdd83"
            "f113a1dd66ab70783ee458c2366bf5fbc016f7c168c43c11d607692a3280e3750"
            "a6154a86b62c48d",
        ),
        (
            "CTR",
            "874d32cd7bdae52cd8630d3ab2bf373e7110e13713caa6a8bfed9d9dd802d0eb"
            "e93128ac0d0f05abcc56237b75fb69207dba11e68ddc4b0118a4c75e7248bbd80"
            "aaba4dd4436642546ec6ca7fa7526f3b0018ed5194c409dc2c1484530b968af5"
            "54984f3",
        ),
        (
            "ECB",
            "aa81f23d1b3abebd68ac560e051a711c2923843beecddb0f7fe4113bd1874e73"
            "cccf3a2a494bb011e154ca2737b4d0eb5978a10316361074ed368d85d5aff5c8"
            "555ea101b0a468e58780a74c7830c561674c183c972a2b48931adf789cb16df30"
            "4e169500f8c95ad",
        ),
    ],
)
def test_triple_des_official_vectors(mode: str, expected: str) -> None:
    iv = "14f67ac044a84da6" if mode != "ECB" else ""
    args = [
        {"option": "Hex", "string": "190da55fb54b9e7dd6de05f43bf3347ef203cd34a5829b23"},
        {"option": "Hex", "string": iv},
        mode,
        "Hex",
        "Hex",
    ]
    assert bake(_INPUT, [{"op": "Triple DES Encrypt", "args": args}]) == expected
    assert bake(expected, [{"op": "Triple DES Decrypt", "args": args}]) == _INPUT


def test_two_key_triple_des_and_no_padding() -> None:
    key = {"option": "Hex", "string": "0123456789abcdeffedcba9876543210"}
    args = [key, {"option": "Hex", "string": ""}, "ECB", "Hex", "Hex"]
    encrypted = bake("0123456789abcdef", [{"op": "Triple DES Encrypt", "args": args}])
    assert isinstance(encrypted, str)
    decrypt_args = [key, args[1], "ECB/NoPadding", "Hex", "Hex"]
    plaintext_with_padding = bake(encrypted, [{"op": "Triple DES Decrypt", "args": decrypt_args}])
    assert plaintext_with_padding == "0123456789abcdef0808080808080808"


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("test", "01FC5A6BE7BC6929AAD3B435B51404EE"),
        (
            "QWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()_+.,?/",
            "6D9DF16655336CA75A3C13DD18BA8156",
        ),
    ],
)
def test_lm_hash_official_vectors(password: str, expected: str) -> None:
    assert bake(password, ["LM Hash"]) == expected


def test_des_rejects_bad_key_and_iv() -> None:
    with pytest.raises(OperationError, match="Invalid key length"):
        bake("", [{"op": "DES Encrypt", "args": [{"option": "Hex", "string": ""}]}])
    with pytest.raises(OperationError, match="Invalid IV length"):
        bake(
            "",
            [
                {
                    "op": "Triple DES Encrypt",
                    "args": [
                        {"option": "Hex", "string": "00" * 24},
                        {"option": "Hex", "string": ""},
                    ],
                }
            ],
        )
