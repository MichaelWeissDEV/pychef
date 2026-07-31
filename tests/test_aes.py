"""Official CyberChef and RFC vectors for the pure-Python AES operations."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_KEY_128 = {"option": "Hex", "string": "00112233445566778899aabbccddeeff"}
_EMPTY_HEX = {"option": "Hex", "string": ""}
_MESSAGE = "The quick brown fox jumps over the lazy dog."


@pytest.mark.parametrize(
    ("mode", "iv", "expected"),
    [
        (
            "CBC",
            "00000000000000000000000000000000",
            "2ef6c3fdb1314b5c2c326a2087fe1a82d5e73bf605ec8431d73e847187fc1c8f"
            "bbe969c177df1ecdf8c13f2f505f9498",
        ),
        (
            "CTR",
            "00000000000000000000000000000000",
            "a98c9e8e3b7c894384d740e4f0f4ed0be2bbb1e0e13a255812c3c6b0a629e4ad7"
            "59c075b2469c6f4fb2c0cf9",
        ),
        (
            "CFB",
            "00112233445566778899aabbccddeeff",
            "369e1c9e5a85b0520f3e61eecc37759246ad0a02cae7a99a3d250ae39cad474338"
            "5375cf63720d52ae8cdfb9",
        ),
        (
            "OFB",
            "00112233445566778899aabbccddeeff",
            "369e1c9e5a85b0520f3e61eecc37759288cb378c5fa9c675bd6c4ede0ae6a925ea"
            "ebc8e0a6162d2a000ddc0f",
        ),
        (
            "ECB",
            "",
            "2ef6c3fdb1314b5c2c326a2087fe1a8238c5a5db7dff38f6f4eb75b2e55cab3d8"
            "d6113eb8d3517223b4545fcdb4c5a48",
        ),
    ],
)
def test_aes_official_mode_vectors(mode: str, iv: str, expected: str) -> None:
    encrypt_args = [
        _KEY_128,
        {"option": "Hex", "string": iv},
        mode,
        "Raw",
        "Hex",
        _EMPTY_HEX,
        "Off",
    ]
    assert bake(_MESSAGE, [{"op": "AES Encrypt", "args": encrypt_args}]) == expected
    decrypt_args = [
        _KEY_128,
        {"option": "Hex", "string": iv},
        16,
        mode,
        "Hex",
        "Raw",
        _EMPTY_HEX,
        _EMPTY_HEX,
        "Off",
    ]
    assert bake(expected, [{"op": "AES Decrypt", "args": decrypt_args}]) == _MESSAGE.encode()


@pytest.mark.parametrize(
    ("key", "ciphertext"),
    [
        (
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ],
)
def test_aes_fips_ecb_vectors(key: str, ciphertext: str) -> None:
    args = [
        {"option": "Hex", "string": key},
        _EMPTY_HEX,
        "ECB/NoPadding",
        "Hex",
        "Hex",
        _EMPTY_HEX,
        "Off",
    ]
    plaintext = "00112233445566778899aabbccddeeff"
    assert bake(plaintext, [{"op": "AES Encrypt", "args": args}]) == ciphertext
    decrypt_args = [*args[:2], 16, args[2], "Hex", "Hex", _EMPTY_HEX, _EMPTY_HEX, "Off"]
    assert bake(ciphertext, [{"op": "AES Decrypt", "args": decrypt_args}]) == plaintext


@pytest.mark.parametrize(
    ("iv", "aad", "ciphertext", "tag"),
    [
        (
            "",
            "",
            "d0bcace0fa3a214b0ac3cbb4ac2caaf97b965f172f66d2a4ec6304a15a4072f1b2"
            "8a6f9b80473f86bfa47b2c",
            "16a3e732a605cc9ca29108f742ca0743",
        ),
        (
            "ffeeddccbbaa99887766554433221100",
            "additional data",
            "daa58faa056c52756aa488aeafbd265b6effcf4eca58220a97b0005b1a9b1e1c9e7"
            "a6725d35f5f79b9493de7",
            "3b5378917f67b0aade9891fc6c291646",
        ),
    ],
)
def test_aes_official_gcm_vectors(iv: str, aad: str, ciphertext: str, tag: str) -> None:
    authenticated_data = {"option": "UTF8", "string": aad}
    encrypt_args = [
        _KEY_128,
        {"option": "Hex", "string": iv},
        "GCM",
        "Raw",
        "Hex",
        authenticated_data,
        "Off",
    ]
    assert bake(_MESSAGE, [{"op": "AES Encrypt", "args": encrypt_args}]) == (
        f"{ciphertext}\n\nTag: {tag}"
    )
    decrypt_args = [
        _KEY_128,
        {"option": "Hex", "string": iv},
        16,
        "GCM",
        "Hex",
        "Raw",
        {"option": "Hex", "string": tag},
        authenticated_data,
        "Off",
    ]
    assert bake(ciphertext, [{"op": "AES Decrypt", "args": decrypt_args}]) == _MESSAGE.encode()


def test_aes_gcm_iv_in_output_and_authentication_failure() -> None:
    iv = "ffeeddccbbaa998877665544"
    args = [
        _KEY_128,
        {"option": "Hex", "string": iv},
        "GCM",
        "Raw",
        "Hex",
        _EMPTY_HEX,
        "Prepend",
    ]
    encrypted = bake("authenticated", [{"op": "AES Encrypt", "args": args}])
    assert isinstance(encrypted, str)
    ciphertext_with_iv, tag_line = encrypted.split("\n\nTag: ")
    decrypt_args = [
        _KEY_128,
        _EMPTY_HEX,
        12,
        "GCM",
        "Hex",
        "Raw",
        {"option": "Hex", "string": tag_line},
        _EMPTY_HEX,
        "From start",
    ]
    assert bake(ciphertext_with_iv, [{"op": "AES Decrypt", "args": decrypt_args}]) == (
        b"authenticated"
    )
    decrypt_args[6] = {"option": "Hex", "string": "00" * 16}
    with pytest.raises(OperationError, match="Unable to decrypt"):
        bake(ciphertext_with_iv, [{"op": "AES Decrypt", "args": decrypt_args}])


_WRAP_VECTORS = [
    (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
    ),
    (
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7",
    ),
    (
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff0001020304050607",
        "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff0001020304050607",
        "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
        "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
    ),
]


@pytest.mark.parametrize(("key", "plaintext", "wrapped"), _WRAP_VECTORS)
def test_aes_key_wrap_official_rfc_vectors(key: str, plaintext: str, wrapped: str) -> None:
    args = [
        {"option": "Hex", "string": key},
        {"option": "Hex", "string": "a6a6a6a6a6a6a6a6"},
        "Hex",
        "Hex",
    ]
    assert bake(plaintext, [{"op": "AES Key Wrap", "args": args}]) == wrapped
    assert bake(wrapped, [{"op": "AES Key Unwrap", "args": args}]) == plaintext


def test_aes_rejects_invalid_lengths_and_padding() -> None:
    with pytest.raises(OperationError, match="Invalid key length"):
        bake("", [{"op": "AES Encrypt", "args": [_EMPTY_HEX]}])
    args = [
        {"option": "Hex", "string": "00" * 16},
        _EMPTY_HEX,
        "ECB/NoPadding",
        "Raw",
        "Hex",
        _EMPTY_HEX,
        "Off",
    ]
    with pytest.raises(OperationError, match="multiple of 16"):
        bake("short", [{"op": "AES Encrypt", "args": args}])
    with pytest.raises(OperationError, match="8n"):
        bake("0011", [{"op": "AES Key Wrap", "args": [args[0]]}])
