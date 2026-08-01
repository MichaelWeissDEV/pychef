"""ECDSA signature conversion between DER, IEEE P1363, JWS, and JSON."""

from __future__ import annotations

import base64
import binascii
import json
import re

from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg

_HEX_RE = re.compile(r"^[a-f\d]{2,}$", re.IGNORECASE)


def _read_length(data: bytes, position: int) -> tuple[int, int]:
    if position >= len(data):
        raise ValueError("Invalid ASN.1 signature")
    first = data[position]
    if first < 0x80:
        return first, position + 1
    width = first & 0x7F
    if width == 0 or width > 4 or position + 1 + width > len(data):
        raise ValueError("Invalid ASN.1 signature")
    return int.from_bytes(data[position + 1 : position + 1 + width], "big"), position + 1 + width


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _parse_der(value: str) -> tuple[bytes, bytes]:
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("Invalid ASN.1 signature") from exc
    if not data or data[0] != 0x30:
        raise ValueError("Invalid ASN.1 signature")
    sequence_length, position = _read_length(data, 1)
    if position + sequence_length != len(data):
        raise ValueError("Invalid ASN.1 signature")
    integers = []
    for _ in range(2):
        if position >= len(data) or data[position] != 0x02:
            raise ValueError("Invalid ASN.1 signature")
        length, position = _read_length(data, position + 1)
        integer = data[position : position + length]
        if len(integer) != length or not integer or integer[0] & 0x80:
            raise ValueError("Invalid ASN.1 signature")
        integers.append(integer)
        position += length
    if position != len(data):
        raise ValueError("Invalid ASN.1 signature")
    return integers[0], integers[1]


def _der_integer(value: bytes) -> bytes:
    normalized = value.lstrip(b"\0") or b"\0"
    if normalized[0] & 0x80:
        normalized = b"\0" + normalized
    return b"\x02" + _encode_length(len(normalized)) + normalized


def _to_der(first: bytes, second: bytes) -> str:
    payload = _der_integer(first) + _der_integer(second)
    return (b"\x30" + _encode_length(len(payload)) + payload).hex()


def _to_p1363(first: bytes, second: bytes) -> bytes:
    first = first.lstrip(b"\0") or b"\0"
    second = second.lstrip(b"\0") or b"\0"
    width = max(len(first), len(second))
    return first.rjust(width, b"\0") + second.rjust(width, b"\0")


def _from_p1363(value: bytes) -> tuple[bytes, bytes]:
    if not value or len(value) % 2:
        raise ValueError("Invalid P1363 signature")
    midpoint = len(value) // 2
    return value[:midpoint], value[midpoint:]


def _base64url_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid JSON Web Signature") from exc


def _detect(value: str) -> str:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return "Raw JSON"
    except json.JSONDecodeError:
        pass
    if _HEX_RE.fullmatch(value):
        if value[:2].lower() == "30":
            try:
                _parse_der(value)
                return "ASN.1 HEX"
            except ValueError:
                pass
        return "P1363 HEX"
    try:
        _from_p1363(_base64url_decode(value))
        return "JSON Web Signature"
    except ValueError as exc:
        raise ValueError("Signature format could not be detected") from exc


def _input_components(value: str, input_format: str) -> tuple[bytes, bytes]:
    if input_format == "ASN.1 HEX":
        return _parse_der(value)
    if input_format == "P1363 HEX":
        try:
            return _from_p1363(bytes.fromhex(value))
        except ValueError as exc:
            raise ValueError("Invalid P1363 signature") from exc
    if input_format == "JSON Web Signature":
        return _from_p1363(_base64url_decode(value))
    if input_format == "Raw JSON":
        parsed = json.loads(value)
        if not isinstance(parsed, dict) or not parsed.get("r"):
            raise ValueError('No "r" value in the signature JSON')
        if not parsed.get("s"):
            raise ValueError('No "s" value in the signature JSON')
        try:
            return bytes.fromhex(str(parsed["r"])), bytes.fromhex(str(parsed["s"]))
        except ValueError as exc:
            raise ValueError("Invalid hexadecimal value in signature JSON") from exc
    raise ValueError("Signature format could not be detected")


@implementation("ECDSA Signature Conversion", category="Ciphers")
def ecdsa_signature_conversion(value: Data, args: Args) -> Data:
    text = to_text(value)
    input_format = str(arg(args, 0, "Auto"))
    output_format = str(arg(args, 1, "ASN.1 HEX"))
    if input_format == "Auto":
        input_format = _detect(text)
    first, second = _input_components(text, input_format)
    der = _to_der(first, second)
    if output_format == "ASN.1 HEX":
        return der
    if output_format == "P1363 HEX":
        return _to_p1363(first, second).hex()
    if output_format == "JSON Web Signature":
        return base64.urlsafe_b64encode(_to_p1363(first, second)).decode().rstrip("=")
    if output_format == "Raw JSON":
        der_first, der_second = _parse_der(der)
        return json.dumps({"r": der_first.hex(), "s": der_second.hex()}, separators=(",", ":"))
    raise ValueError(f"Unsupported ECDSA signature output format: {output_format}")
