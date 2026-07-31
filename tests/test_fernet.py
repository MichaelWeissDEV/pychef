"""Official CyberChef Fernet examples and format validation."""

from __future__ import annotations

import base64

import pytest

from pychef import OperationError, bake

_KEY = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
_MESSAGE = "This is a secret message.\n"


def test_fernet_official_decrypt_vector() -> None:
    token = (
        "gAAAAABce-Tycae8klRxhDX2uenJ-uwV8-A1XZ2HRnfOXlNzkKKfRxviNLlgtemh"
        "T_fd1Fw5P_zFUAjd69zaJBQyWppAxVV00SExe77ql8c5n62HYJOnoIU="
    )
    assert (
        bake(
            token,
            [{"op": "Fernet Decrypt", "args": ["VGhpc0lzVGhpcnR5VHdvQ2hhcmFjdGVyc0xvbmdLZXk="]}],
        )
        == _MESSAGE
    )


def test_fernet_encrypt_format_and_round_trip() -> None:
    token = bake(_MESSAGE, [{"op": "Fernet Encrypt", "args": [_KEY]}])
    assert isinstance(token, str)
    decoded = base64.urlsafe_b64decode(token)
    assert decoded[0] == 0x80
    assert len(decoded) >= 73
    assert bake(token, [{"op": "Fernet Decrypt", "args": [_KEY]}]) == _MESSAGE
    empty = bake("", [{"op": "Fernet Encrypt", "args": [_KEY]}])
    assert bake(empty, [{"op": "Fernet Decrypt", "args": [_KEY]}]) == ""


def test_fernet_official_error_cases_and_authentication() -> None:
    with pytest.raises(OperationError, match="Invalid version"):
        bake("", [{"op": "Fernet Decrypt", "args": [_KEY]}])
    with pytest.raises(OperationError, match="Secret must be 32"):
        bake(_MESSAGE, [{"op": "Fernet Encrypt", "args": [""]}])
    with pytest.raises(OperationError, match="Secret must be 32"):
        bake("gAAAAA", [{"op": "Fernet Decrypt", "args": [""]}])
    token = bake(_MESSAGE, [{"op": "Fernet Encrypt", "args": [_KEY]}])
    assert isinstance(token, str)
    tampered = bytearray(base64.urlsafe_b64decode(token))
    tampered[-1] ^= 1
    with pytest.raises(OperationError, match="Invalid signature"):
        bake(
            base64.urlsafe_b64encode(tampered).decode(),
            [{"op": "Fernet Decrypt", "args": [_KEY]}],
        )
