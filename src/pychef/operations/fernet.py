"""Dependency-free implementation of the Fernet authenticated-token format."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from ..registry import operation
from ..types import Args, Data, to_bytes
from ._utils import arg
from .aes import _block_mode

_VERSION = 0x80


def _secret(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Error: Secret must be 32 url-safe base64-encoded bytes.") from exc
    if len(decoded) != 32:
        raise ValueError("Error: Secret must be 32 url-safe base64-encoded bytes.")
    return decoded


def _token_bytes(value: Data) -> bytes:
    try:
        return base64.b64decode(to_bytes(value), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Error: Invalid token") from exc


@operation("Fernet Encrypt", category="Encryption")
def fernet_encrypt(value: Data, args: Args) -> Data:
    secret = _secret(str(arg(args, 0, "")))
    signing_key, encryption_key = secret[:16], secret[16:]
    timestamp = int(time.time()).to_bytes(8, "big")
    iv = secrets.token_bytes(16)
    ciphertext = _block_mode(
        to_bytes(value),
        encryption_key,
        iv,
        "CBC",
        decrypting=False,
        no_padding=False,
    )
    payload = bytes([_VERSION]) + timestamp + iv + ciphertext
    signature = hmac.new(signing_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + signature).decode()


@operation("Fernet Decrypt", category="Encryption")
def fernet_decrypt(value: Data, args: Args) -> Data:
    secret = _secret(str(arg(args, 0, "")))
    token = _token_bytes(value)
    if not token or token[0] != _VERSION:
        raise ValueError("Error: Invalid version")
    if len(token) < 73 or (len(token) - 57) % 16:
        raise ValueError("Error: Invalid token")
    signing_key, encryption_key = secret[:16], secret[16:]
    payload, signature = token[:-32], token[-32:]
    expected = hmac.new(signing_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Error: Invalid signature")
    plaintext = _block_mode(
        payload[25:],
        encryption_key,
        payload[9:25],
        "CBC",
        decrypting=True,
        no_padding=False,
    )
    return plaintext.decode("utf-8", "replace")
