"""Dependency-free ChaCha stream cipher compatible with CyberChef."""

from __future__ import annotations

import base64
import re
import struct
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int

_MASK32 = 0xFFFFFFFF


def _stream_bytes(value: Any, *, integer_length: int | None = None) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        option = str(value.get("option", "UTF8"))
    else:
        text, option = str(value), "UTF8"
    if option == "Integer":
        if integer_length is None:
            raise ValueError("integer length is required")
        return int(text).to_bytes(integer_length, "little")
    if option == "Hex":
        return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", text))
    if option == "Base64":
        return base64.b64decode(text)
    if option == "Latin1":
        return text.encode("latin-1")
    return text.encode()


def _rotate32(value: int, distance: int) -> int:
    return ((value << distance) | (value >> (32 - distance))) & _MASK32


def _chacha_quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotate32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotate32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotate32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotate32(state[b] ^ state[c], 7)


def _chacha_block(key: bytes, nonce: bytes, counter: int, rounds: int) -> bytes:
    constant = b"expand 16-byte k" if len(key) == 16 else b"expand 32-byte k"
    expanded_key = key + key if len(key) == 16 else key
    counter_length = 16 - len(nonce)
    material = constant + expanded_key + counter.to_bytes(counter_length, "little") + nonce
    initial = list(struct.unpack("<16I", material))
    state = initial.copy()
    for _round in range(rounds // 2):
        _chacha_quarter(state, 0, 4, 8, 12)
        _chacha_quarter(state, 1, 5, 9, 13)
        _chacha_quarter(state, 2, 6, 10, 14)
        _chacha_quarter(state, 3, 7, 11, 15)
        _chacha_quarter(state, 0, 5, 10, 15)
        _chacha_quarter(state, 1, 6, 11, 12)
        _chacha_quarter(state, 2, 7, 8, 13)
        _chacha_quarter(state, 3, 4, 9, 14)
    result = ((word + original) & _MASK32 for word, original in zip(state, initial, strict=True))
    return struct.pack("<16I", *result)


def _salsa_quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[b] ^= _rotate32((state[a] + state[d]) & _MASK32, 7)
    state[c] ^= _rotate32((state[b] + state[a]) & _MASK32, 9)
    state[d] ^= _rotate32((state[c] + state[b]) & _MASK32, 13)
    state[a] ^= _rotate32((state[d] + state[c]) & _MASK32, 18)


def _salsa_permute(state: list[int], rounds: int) -> None:
    for _round in range(rounds // 2):
        _salsa_quarter(state, 0, 4, 8, 12)
        _salsa_quarter(state, 5, 9, 13, 1)
        _salsa_quarter(state, 10, 14, 2, 6)
        _salsa_quarter(state, 15, 3, 7, 11)
        _salsa_quarter(state, 0, 1, 2, 3)
        _salsa_quarter(state, 5, 6, 7, 4)
        _salsa_quarter(state, 10, 11, 8, 9)
        _salsa_quarter(state, 15, 12, 13, 14)


def _salsa_state(key: bytes, middle: bytes) -> list[int]:
    constant = b"expand 16-byte k" if len(key) == 16 else b"expand 32-byte k"
    expanded_key = key + key if len(key) == 16 else key
    material = (
        constant[:4]
        + expanded_key[:16]
        + constant[4:8]
        + middle
        + constant[8:12]
        + expanded_key[16:]
        + constant[12:]
    )
    return list(struct.unpack("<16I", material))


def _salsa_block(key: bytes, nonce: bytes, counter: int, rounds: int) -> bytes:
    initial = _salsa_state(key, nonce + counter.to_bytes(8, "little"))
    state = initial.copy()
    _salsa_permute(state, rounds)
    return struct.pack(
        "<16I",
        *((word + original) & _MASK32 for word, original in zip(state, initial, strict=True)),
    )


def _hsalsa(key: bytes, nonce: bytes, rounds: int) -> bytes:
    state = _salsa_state(key, nonce)
    _salsa_permute(state, rounds)
    return struct.pack("<8I", *(state[index] for index in (0, 5, 10, 15, 6, 7, 8, 9)))


def _stream_result(data: bytes, block_function: Any, counter: int, output_format: str) -> Data:
    output = bytearray()
    for position in range(0, len(data), 64):
        stream = block_function(counter + position // 64)
        block = data[position : position + 64]
        output.extend(left ^ right for left, right in zip(block, stream, strict=False))
    if output_format == "Hex":
        return bytes(output).hex(" ")
    return bytes(output)


@operation("ChaCha", category="Ciphers")
def chacha(value: Data, args: Args) -> Data:
    key = _stream_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    nonce_arg = arg(args, 1, {"option": "Hex", "string": ""})
    nonce_option = str(nonce_arg.get("option", "UTF8")) if isinstance(nonce_arg, dict) else "UTF8"
    nonce = _stream_bytes(nonce_arg, integer_length=12 if nonce_option == "Integer" else None)
    counter = require_int(arg(args, 2, 0), name="counter")
    rounds = require_int(arg(args, 3, "20"), name="rounds")
    input_format = str(arg(args, 4, "Hex"))
    output_format = str(arg(args, 5, "Raw"))
    if len(key) not in {16, 32}:
        raise ValueError("ChaCha requires a 16-byte or 32-byte key")
    if len(nonce) not in {8, 12}:
        raise ValueError("ChaCha requires an 8-byte or 12-byte nonce")
    if rounds not in {8, 12, 20}:
        raise ValueError("ChaCha rounds must be 8, 12, or 20")
    data = bytes.fromhex(to_text(value)) if input_format == "Hex" else to_bytes(value)
    return _stream_result(
        data,
        lambda block_counter: _chacha_block(key, nonce, block_counter, rounds),
        counter,
        output_format,
    )


def _salsa(value: Data, args: Args, *, extended: bool) -> Data:
    name = "XSalsa20" if extended else "Salsa20"
    key = _stream_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    nonce_arg = arg(args, 1, {"option": "Hex", "string": ""})
    nonce_length = 24 if extended else 8
    nonce = _stream_bytes(nonce_arg, integer_length=nonce_length)
    counter = require_int(arg(args, 2, 0), name="counter")
    rounds = require_int(arg(args, 3, "20"), name="rounds")
    input_format = str(arg(args, 4, "Hex"))
    output_format = str(arg(args, 5, "Raw"))
    if len(key) not in {16, 32}:
        raise ValueError(f"{name} requires a 16-byte or 32-byte key")
    if len(nonce) != nonce_length:
        raise ValueError(f"{name} requires a {nonce_length}-byte nonce")
    if rounds not in {8, 12, 20}:
        raise ValueError(f"{name} rounds must be 8, 12, or 20")
    data = bytes.fromhex(to_text(value)) if input_format == "Hex" else to_bytes(value)
    if extended:
        key = _hsalsa(key, nonce[:16], rounds)
        nonce = nonce[16:]
    return _stream_result(
        data,
        lambda block_counter: _salsa_block(key, nonce, block_counter, rounds),
        counter,
        output_format,
    )


@operation("Salsa20", category="Ciphers")
def salsa20(value: Data, args: Args) -> Data:
    return _salsa(value, args, extended=False)


@operation("XSalsa20", category="Ciphers")
def xsalsa20(value: Data, args: Args) -> Data:
    return _salsa(value, args, extended=True)
