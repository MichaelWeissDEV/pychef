"""HMAC JWT and Flask session operations using only the standard library."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import zlib
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _urlsafe_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _toggle_bytes(value: Any) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        option = str(value.get("option", "UTF8")).upper()
    else:
        text, option = str(value), "UTF8"
    if option == "HEX":
        return bytes.fromhex(text)
    if option == "BASE64":
        return base64.b64decode(text)
    if option == "LATIN1":
        return text.encode("latin-1")
    return text.encode()


_JWT_HMAC = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


@operation("JWT Sign", category="Authentication")
def jwt_sign(value: Data, args: Args) -> str:
    key = str(arg(args, 0, "")).encode()
    algorithm = str(arg(args, 1, "HS256"))
    custom_header = json.loads(str(arg(args, 2, "{}")))
    if algorithm not in _JWT_HMAC:
        raise ValueError(
            "dependency-free JWT Sign supports HS256, HS384, and HS512; "
            "asymmetric algorithms require a cryptographic backend"
        )
    if not key:
        raise ValueError("JWT HMAC secret must not be empty")
    payload = json.loads(to_text(value))
    header = {"alg": algorithm, "typ": "JWT", **custom_header}
    encoded_header = _urlsafe_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _urlsafe_encode(json.dumps(payload, separators=(",", ":")).encode())
    signed = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(key, signed.encode(), _JWT_HMAC[algorithm]).digest()
    return f"{signed}.{_urlsafe_encode(signature)}"


@operation("JWT Verify", category="Authentication")
def jwt_verify(value: Data, args: Args) -> str:
    token = to_text(value).strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain three dot-separated parts")
    try:
        header = json.loads(_urlsafe_decode(parts[0]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JWT header") from exc
    algorithm = header.get("alg") if isinstance(header, dict) else None
    if algorithm not in _JWT_HMAC:
        raise ValueError(
            "dependency-free JWT Verify only accepts HS256, HS384, and HS512 "
            "and rejects asymmetric or unsigned tokens"
        )
    key = str(arg(args, 0, "")).encode()
    expected = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), _JWT_HMAC[algorithm]).digest()
    try:
        supplied = _urlsafe_decode(parts[2])
    except ValueError as exc:
        raise ValueError("invalid JWT signature encoding") from exc
    if not hmac.compare_digest(expected, supplied):
        raise ValueError("invalid JWT signature")
    try:
        payload = json.loads(_urlsafe_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JWT payload") from exc
    return json.dumps(payload, ensure_ascii=False, indent=4)


def _flask_payload(token: str) -> Any:
    parts = token.split(".")
    compressed = token.startswith(".")
    payload_part = parts[1] if compressed else parts[0]
    raw = _urlsafe_decode(payload_part)
    if compressed:
        raw = zlib.decompress(raw)
    return json.loads(raw)


@operation("Flask Session Decode", category="Authentication")
def flask_session_decode(value: Data, _args: Args) -> str:
    return json.dumps(_flask_payload(to_text(value).strip()), ensure_ascii=False, indent=4)


def _flask_signature(value: str, secret: bytes, salt: bytes, algorithm: str) -> bytes:
    try:
        digest = getattr(hashlib, algorithm.lower())
    except AttributeError as exc:
        raise ValueError(f"unsupported Flask digest: {algorithm}") from exc
    derived = hmac.new(secret, salt, digest).digest()
    return hmac.new(derived, value.encode(), digest).digest()


@operation("Flask Session Sign", category="Authentication")
def flask_session_sign(value: Data, args: Args) -> str:
    secret = _toggle_bytes(arg(args, 0, {"string": "", "option": "UTF8"}))
    salt = _toggle_bytes(arg(args, 1, {"string": "cookie-session", "option": "UTF8"}))
    algorithm = str(arg(args, 2, "sha1"))
    if not secret:
        raise ValueError("Flask session secret must not be empty")
    payload = json.dumps(
        json.loads(to_text(value)), separators=(",", ":"), ensure_ascii=False
    ).encode()
    compressed = zlib.compress(payload)
    if len(compressed) < len(payload) - 1:
        encoded_payload = "." + _urlsafe_encode(compressed)
    else:
        encoded_payload = _urlsafe_encode(payload)
    timestamp = _urlsafe_encode(int(time.time()).to_bytes(4, "big"))
    unsigned = f"{encoded_payload}.{timestamp}"
    signature = _flask_signature(unsigned, secret, salt, algorithm)
    return f"{unsigned}.{_urlsafe_encode(signature)}"


@operation("Flask Session Verify", category="Authentication")
def flask_session_verify(value: Data, args: Args) -> str:
    token = to_text(value).strip()
    secret = _toggle_bytes(arg(args, 0, {"string": "", "option": "UTF8"}))
    salt = _toggle_bytes(arg(args, 1, {"string": "cookie-session", "option": "UTF8"}))
    algorithm = str(arg(args, 2, "sha1"))
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        raise ValueError("invalid Flask session token")
    try:
        supplied = _urlsafe_decode(parts[1])
    except ValueError:
        return "Invalid signature!"
    expected = _flask_signature(parts[0], secret, salt, algorithm)
    if not hmac.compare_digest(expected, supplied):
        return "Invalid signature!"
    return json.dumps(
        {"valid": True, "payload": _flask_payload(token)}, ensure_ascii=False, indent=4
    )
