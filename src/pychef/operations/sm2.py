"""Pure-Python SM2 public-key encryption over the sm2p256v1 curve."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg
from .public_key import _Curve, _point_mul

_SM2 = _Curve(
    "sm2p256v1",
    "1.2.156.10197.1.301",
    int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16),
    int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
    int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16),
    int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
    int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16),
    int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16),
)
_MASK32 = 0xFFFFFFFF


def _rotate_left(value: int, amount: int) -> int:
    amount %= 32
    return ((value << amount) | (value >> (32 - amount))) & _MASK32


def _sm3(data: bytes) -> bytes:
    """GB/T 32905 SM3, used when the platform has no native implementation."""
    try:
        return hashlib.new("sm3", data).digest()
    except ValueError:
        pass
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\0" * ((56 - len(padded) % 64) % 64) + bit_length.to_bytes(8, "big")
    state = [
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E,
    ]
    for offset in range(0, len(padded), 64):
        words = [
            int.from_bytes(padded[offset + index : offset + index + 4], "big")
            for index in range(0, 64, 4)
        ]
        for index in range(16, 68):
            value = words[index - 16] ^ words[index - 9] ^ _rotate_left(words[index - 3], 15)
            value ^= _rotate_left(value, 15) ^ _rotate_left(value, 23)
            words.append((value ^ _rotate_left(words[index - 13], 7) ^ words[index - 6]) & _MASK32)
        derived = [words[index] ^ words[index + 4] for index in range(64)]
        a, b, c, d, e, f, g, h = state
        for index in range(64):
            constant = 0x79CC4519 if index < 16 else 0x7A879D8A
            ss1 = _rotate_left(
                (_rotate_left(a, 12) + e + _rotate_left(constant, index)) & _MASK32,
                7,
            )
            ss2 = ss1 ^ _rotate_left(a, 12)
            ff = a ^ b ^ c if index < 16 else (a & b) | (a & c) | (b & c)
            gg = e ^ f ^ g if index < 16 else (e & f) | ((~e) & g)
            tt1 = (ff + d + ss2 + derived[index]) & _MASK32
            tt2 = (gg + h + ss1 + words[index]) & _MASK32
            d = c
            c = _rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotate_left(f, 19)
            f = e
            e = tt2 ^ _rotate_left(tt2, 9) ^ _rotate_left(tt2, 17)
        state = [old ^ new for old, new in zip(state, (a, b, c, d, e, f, g, h), strict=True)]
    return b"".join(word.to_bytes(4, "big") for word in state)


def _sm2_kdf(shared: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 1
    while len(output) < length:
        output.extend(_sm3(shared + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(output[:length])


def _hex_key(value: object, name: str) -> int:
    text = str(value)
    if len(text) != 64:
        raise ValueError(f"{name} must be 32 bytes in hexadecimal")
    try:
        number = int(text, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be 32 bytes in hexadecimal") from exc
    if not 0 < number < _SM2.p:
        raise ValueError(f"Invalid {name}")
    return number


def _validate_public(point: tuple[int, int]) -> None:
    x, y = point
    if (y * y - x * x * x - _SM2.a * x - _SM2.b) % _SM2.p:
        raise ValueError("SM2 public key is not on sm2p256v1")
    if _point_mul(_SM2, _SM2.n, point) is not None:
        raise ValueError("Invalid SM2 public key order")


@implementation("SM2 Encrypt", category="Crypto")
def sm2_encrypt(value: Data, args: Args) -> Data:
    public = (
        _hex_key(arg(args, 0, "DEADBEEF"), "Public Key X"),
        _hex_key(arg(args, 1, "DEADBEEF"), "Public Key Y"),
    )
    _validate_public(public)
    output_format = str(arg(args, 2, "C1C3C2"))
    if output_format not in {"C1C3C2", "C1C2C3"}:
        raise ValueError("Invalid SM2 output format")
    if str(arg(args, 3, "sm2p256v1")) != "sm2p256v1":
        raise ValueError("Unsupported SM2 curve")
    message = to_bytes(value)
    while True:
        scalar = secrets.randbelow(_SM2.n - 1) + 1
        c1 = _point_mul(_SM2, scalar)
        shared = _point_mul(_SM2, scalar, public)
        if c1 is None or shared is None:
            continue
        x2 = shared[0].to_bytes(32, "big")
        y2 = shared[1].to_bytes(32, "big")
        mask = _sm2_kdf(x2 + y2, len(message))
        if message and not any(mask):
            continue
        c2 = bytes(left ^ right for left, right in zip(message, mask, strict=True))
        c3 = _sm3(x2 + message + y2)
        c1_bytes = c1[0].to_bytes(32, "big") + c1[1].to_bytes(32, "big")
        result = c1_bytes + (c3 + c2 if output_format == "C1C3C2" else c2 + c3)
        return result.hex()


@implementation("SM2 Decrypt", category="Crypto")
def sm2_decrypt(value: Data, args: Args) -> Data:
    private = _hex_key(arg(args, 0, "DEADBEEF"), "Private Key")
    if private >= _SM2.n:
        raise ValueError("Invalid SM2 private key")
    input_format = str(arg(args, 1, "C1C3C2"))
    if input_format not in {"C1C3C2", "C1C2C3"}:
        raise ValueError("Invalid SM2 input format")
    if str(arg(args, 2, "sm2p256v1")) != "sm2p256v1":
        raise ValueError("Unsupported SM2 curve")
    try:
        ciphertext = bytes.fromhex(to_text(value))
    except ValueError as exc:
        raise ValueError("SM2 ciphertext must be hexadecimal") from exc
    if len(ciphertext) < 96:
        raise ValueError("SM2 ciphertext is too short")
    c1 = (int.from_bytes(ciphertext[:32], "big"), int.from_bytes(ciphertext[32:64], "big"))
    _validate_public(c1)
    if input_format == "C1C3C2":
        c3, c2 = ciphertext[64:96], ciphertext[96:]
    else:
        c2, c3 = ciphertext[64:-32], ciphertext[-32:]
    shared = _point_mul(_SM2, private, c1)
    if shared is None:
        raise ValueError("Invalid SM2 shared point")
    x2 = shared[0].to_bytes(32, "big")
    y2 = shared[1].to_bytes(32, "big")
    mask = _sm2_kdf(x2 + y2, len(c2))
    if c2 and not any(mask):
        raise ValueError("Invalid all-zero SM2 KDF output")
    plaintext = bytes(left ^ right for left, right in zip(c2, mask, strict=True))
    if not hmac.compare_digest(c3, _sm3(x2 + plaintext + y2)):
        raise ValueError("SM2 integrity check failed")
    return plaintext
