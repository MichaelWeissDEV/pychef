"""Dependency-free TEA-family and RC4-derived ciphers."""

from __future__ import annotations

import base64
import secrets
import struct
from collections.abc import Callable
from functools import lru_cache
from typing import Any

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int

_MASK32 = 0xFFFFFFFF
_DELTA = 0x9E3779B9
_BLOCK_SIZE = 8
_BlockCipher = Callable[[bytes, bytes], bytes]


def _toggle_bytes(value: Any) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        option = str(value.get("option", "UTF8"))
    else:
        text, option = str(value or ""), "UTF8"
    normalized = option.upper()
    if normalized == "HEX":
        return bytes.fromhex(text)
    if normalized == "BASE64":
        return base64.b64decode(text)
    if normalized == "LATIN1":
        return text.encode("latin-1")
    if normalized in {"UTF16", "UTF16BE"}:
        return text.encode("utf-16be")
    if normalized == "UTF16LE":
        return text.encode("utf-16le")
    return text.encode()


def _formatted_input(value: Data, input_format: str) -> bytes:
    normalized = input_format.upper()
    if normalized == "HEX":
        return bytes.fromhex(to_text(value))
    if normalized == "BASE64":
        return base64.b64decode(to_bytes(value))
    if normalized == "LATIN1":
        return to_text(value).encode("latin-1") if isinstance(value, str) else value
    if normalized in {"UTF16", "UTF16BE"}:
        return to_text(value).encode("utf-16be")
    if normalized == "UTF16LE":
        return to_text(value).encode("utf-16le")
    return to_bytes(value)


def _formatted_output(value: bytes, output_format: str) -> Data:
    normalized = output_format.upper()
    if normalized == "HEX":
        return value.hex()
    if normalized == "BASE64":
        return base64.b64encode(value).decode()
    if normalized == "LATIN1":
        return value.decode("latin-1")
    if normalized in {"UTF16", "UTF16BE"}:
        return value.decode("utf-16be", "replace")
    if normalized == "UTF16LE":
        return value.decode("utf-16le", "replace")
    if normalized == "UTF8":
        return value.decode("utf-8", "replace")
    return value


def _tea_encrypt_block(block: bytes, key: bytes) -> bytes:
    left, right = struct.unpack(">2I", block)
    words = struct.unpack(">4I", key)
    total = 0
    for _ in range(32):
        total = (total + _DELTA) & _MASK32
        left = (
            left + (((right << 4) + words[0]) ^ (right + total) ^ ((right >> 5) + words[1]))
        ) & _MASK32
        right = (
            right + (((left << 4) + words[2]) ^ (left + total) ^ ((left >> 5) + words[3]))
        ) & _MASK32
    return struct.pack(">2I", left, right)


def _tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    left, right = struct.unpack(">2I", block)
    words = struct.unpack(">4I", key)
    total = (_DELTA * 32) & _MASK32
    for _ in range(32):
        right = (
            right - (((left << 4) + words[2]) ^ (left + total) ^ ((left >> 5) + words[3]))
        ) & _MASK32
        left = (
            left - (((right << 4) + words[0]) ^ (right + total) ^ ((right >> 5) + words[1]))
        ) & _MASK32
        total = (total - _DELTA) & _MASK32
    return struct.pack(">2I", left, right)


def _xtea_encrypt_block(block: bytes, key: bytes, rounds: int) -> bytes:
    left, right = struct.unpack(">2I", block)
    words = struct.unpack(">4I", key)
    total = 0
    for _ in range(rounds):
        left = (
            left + ((((right << 4) ^ (right >> 5)) + right) ^ (total + words[total & 3]))
        ) & _MASK32
        total = (total + _DELTA) & _MASK32
        right = (
            right + ((((left << 4) ^ (left >> 5)) + left) ^ (total + words[(total >> 11) & 3]))
        ) & _MASK32
    return struct.pack(">2I", left, right)


def _xtea_decrypt_block(block: bytes, key: bytes, rounds: int) -> bytes:
    left, right = struct.unpack(">2I", block)
    words = struct.unpack(">4I", key)
    total = (_DELTA * rounds) & _MASK32
    for _ in range(rounds):
        right = (
            right - ((((left << 4) ^ (left >> 5)) + left) ^ (total + words[(total >> 11) & 3]))
        ) & _MASK32
        total = (total - _DELTA) & _MASK32
        left = (
            left + -((((right << 4) ^ (right >> 5)) + right) ^ (total + words[total & 3]))
        ) & _MASK32
    return struct.pack(">2I", left, right)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _pad(data: bytes, padding: str) -> bytes:
    remainder = len(data) % _BLOCK_SIZE
    if remainder == 0 and padding != "PKCS5":
        return data
    count = _BLOCK_SIZE if remainder == 0 else _BLOCK_SIZE - remainder
    if padding == "NO":
        raise ValueError("input length is not a multiple of 8 bytes and no padding was requested")
    if padding == "PKCS5":
        return data + bytes([count]) * count
    if padding == "ZERO":
        return data + bytes(count)
    if padding == "RANDOM":
        return data + secrets.token_bytes(count)
    if padding == "BIT":
        return data + b"\x80" + bytes(count - 1)
    raise ValueError(f"unknown padding type: {padding}")


def _unpad(data: bytes, padding: str) -> bytes:
    if not data or padding in {"NO", "ZERO", "RANDOM"}:
        return data
    if padding == "PKCS5":
        count = data[-1]
        if not 1 <= count <= _BLOCK_SIZE or data[-count:] != bytes([count]) * count:
            raise ValueError("invalid PKCS#5 padding")
        return data[:-count]
    if padding == "BIT":
        stripped = data.rstrip(b"\0")
        if not stripped or stripped[-1] != 0x80:
            raise ValueError("invalid BIT padding")
        return stripped[:-1]
    raise ValueError(f"unknown padding type: {padding}")


def _increment(counter: bytes) -> bytes:
    return ((int.from_bytes(counter, "big") + 1) & ((1 << 64) - 1)).to_bytes(8, "big")


def _encrypt_mode(
    data: bytes, key: bytes, iv: bytes, mode: str, padding: str, encrypt: _BlockCipher
) -> bytes:
    if not data:
        return b""
    if mode in {"ECB", "CBC"}:
        data = _pad(data, padding)
    output = bytearray()
    feedback = iv
    for offset in range(0, len(data), _BLOCK_SIZE):
        block = data[offset : offset + _BLOCK_SIZE]
        if mode == "ECB":
            output.extend(encrypt(block, key))
        elif mode == "CBC":
            feedback = encrypt(_xor(block, feedback), key)
            output.extend(feedback)
        elif mode == "CFB":
            stream = encrypt(feedback, key)
            full = _xor(block.ljust(_BLOCK_SIZE, b"\0"), stream)
            output.extend(full[: len(block)])
            feedback = full
        elif mode == "OFB":
            feedback = encrypt(feedback, key)
            output.extend(_xor(block, feedback[: len(block)]))
        elif mode == "CTR":
            stream = encrypt(feedback, key)
            output.extend(_xor(block, stream[: len(block)]))
            feedback = _increment(feedback)
        else:
            raise ValueError(f"invalid block cipher mode: {mode}")
    return bytes(output)


def _decrypt_mode(
    data: bytes,
    key: bytes,
    iv: bytes,
    mode: str,
    padding: str,
    encrypt: _BlockCipher,
    decrypt: _BlockCipher,
) -> bytes:
    if not data:
        return b""
    if mode in {"ECB", "CBC"} and len(data) % _BLOCK_SIZE:
        raise ValueError("ciphertext length must be a multiple of 8 bytes")
    output = bytearray()
    feedback = iv
    for offset in range(0, len(data), _BLOCK_SIZE):
        block = data[offset : offset + _BLOCK_SIZE]
        if mode == "ECB":
            output.extend(decrypt(block, key))
        elif mode == "CBC":
            output.extend(_xor(decrypt(block, key), feedback))
            feedback = block
        elif mode == "CFB":
            stream = encrypt(feedback, key)
            output.extend(_xor(block, stream[: len(block)]))
            feedback = block.ljust(_BLOCK_SIZE, b"\0")
        elif mode == "OFB":
            feedback = encrypt(feedback, key)
            output.extend(_xor(block, feedback[: len(block)]))
        elif mode == "CTR":
            stream = encrypt(feedback, key)
            output.extend(_xor(block, stream[: len(block)]))
            feedback = _increment(feedback)
        else:
            raise ValueError(f"invalid block cipher mode: {mode}")
    result = bytes(output)
    return _unpad(result, padding) if mode in {"ECB", "CBC"} else result


def _tea_operation(value: Data, args: Args, *, extended: bool, decrypting: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""})) or bytes(8)
    mode = str(arg(args, 2, "CBC"))
    input_format = str(arg(args, 3, "Raw"))
    output_format = str(arg(args, 4, "Hex"))
    padding = str(arg(args, 5, "PKCS5"))
    rounds = require_int(arg(args, 6, 32), name="rounds") if extended else 32
    if len(key) != 16:
        raise ValueError("TEA and XTEA require a 16-byte key")
    if mode != "ECB" and len(iv) != 8:
        raise ValueError("TEA and XTEA require an 8-byte IV")
    if not 1 <= rounds <= 255:
        raise ValueError("rounds must be between 1 and 255")
    data = _formatted_input(value, input_format)
    if extended:

        def encrypt(block: bytes, secret: bytes) -> bytes:
            return _xtea_encrypt_block(block, secret, rounds)

        def decrypt(block: bytes, secret: bytes) -> bytes:
            return _xtea_decrypt_block(block, secret, rounds)
    else:
        encrypt, decrypt = _tea_encrypt_block, _tea_decrypt_block
    result = (
        _decrypt_mode(data, key, iv, mode, padding, encrypt, decrypt)
        if decrypting
        else _encrypt_mode(data, key, iv, mode, padding, encrypt)
    )
    return _formatted_output(result, output_format)


@implementation("TEA Encrypt", category="Ciphers")
def tea_encrypt(value: Data, args: Args) -> Data:
    return _tea_operation(value, args, extended=False, decrypting=False)


@implementation("TEA Decrypt", category="Ciphers")
def tea_decrypt(value: Data, args: Args) -> Data:
    return _tea_operation(value, args, extended=False, decrypting=True)


@implementation("XTEA Encrypt", category="Ciphers")
def xtea_encrypt(value: Data, args: Args) -> Data:
    return _tea_operation(value, args, extended=True, decrypting=False)


@implementation("XTEA Decrypt", category="Ciphers")
def xtea_decrypt(value: Data, args: Args) -> Data:
    return _tea_operation(value, args, extended=True, decrypting=True)


def _little_words(data: bytes, include_length: bool) -> list[int]:
    words = [0] * ((len(data) + 3) // 4 + (1 if include_length else 0))
    for index, byte in enumerate(data):
        words[index >> 2] |= byte << ((index & 3) << 3)
    if include_length:
        words[-1] = len(data)
    return words


def _little_bytes(words: list[int], include_length: bool) -> bytes:
    length = len(words) * 4
    if include_length:
        claimed = words[-1]
        length -= 4
        if claimed < length - 3 or claimed > length:
            raise ValueError("invalid XXTEA data")
        length = claimed
    return bytes((words[index >> 2] >> ((index & 3) << 3)) & 0xFF for index in range(length))


def _xxtea_mix(total: int, y: int, z: int, position: int, e: int, key: list[int]) -> int:
    left = ((z >> 5) ^ ((y << 2) & _MASK32)) + ((y >> 3) ^ ((z << 4) & _MASK32))
    right = (total ^ y) + (key[(position & 3) ^ e] ^ z)
    return (left ^ right) & _MASK32


def _xxtea(value: Data, args: Args, *, decrypting: bool) -> bytes:
    data = to_bytes(value)
    if not data:
        return data
    key_bytes = _toggle_bytes(arg(args, 0, {"option": "UTF8", "string": ""}))
    key = _little_words(key_bytes.ljust(16, b"\0"), False)
    key = [*key, 0, 0, 0, 0][:4]
    words = _little_words(data, not decrypting)
    n = len(words) - 1
    rounds = 6 + 52 // len(words)
    if decrypting:
        total = (rounds * _DELTA) & _MASK32
        y = words[0]
        while total:
            e = (total >> 2) & 3
            for position in range(n, 0, -1):
                z = words[position - 1]
                words[position] = (
                    words[position] - _xxtea_mix(total, y, z, position, e, key)
                ) & _MASK32
                y = words[position]
            z = words[n]
            words[0] = (words[0] - _xxtea_mix(total, y, z, 0, e, key)) & _MASK32
            y = words[0]
            total = (total - _DELTA) & _MASK32
    else:
        total = 0
        z = words[n]
        for _ in range(rounds):
            total = (total + _DELTA) & _MASK32
            e = (total >> 2) & 3
            for position in range(n):
                y = words[position + 1]
                words[position] = (
                    words[position] + _xxtea_mix(total, y, z, position, e, key)
                ) & _MASK32
                z = words[position]
            y = words[0]
            words[n] = (words[n] + _xxtea_mix(total, y, z, n, e, key)) & _MASK32
            z = words[n]
    return _little_bytes(words, decrypting)


@implementation("XXTEA Encrypt", category="Ciphers")
def xxtea_encrypt(value: Data, args: Args) -> bytes:
    return _xxtea(value, args, decrypting=False)


@implementation("XXTEA Decrypt", category="Ciphers")
def xxtea_decrypt(value: Data, args: Args) -> bytes:
    return _xxtea(value, args, decrypting=True)


_PRESENT_SBOX = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)
_PRESENT_SBOX_INVERSE = (5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10)
_PRESENT_PBOX = tuple((16 * position) % 63 if position < 63 else 63 for position in range(64))
_PRESENT_PBOX_INVERSE = tuple(_PRESENT_PBOX.index(position) for position in range(64))


def _present_substitute(state: int, substitution: tuple[int, ...]) -> int:
    result = 0
    for position in range(16):
        result |= substitution[(state >> (position * 4)) & 0xF] << (position * 4)
    return result


def _present_permute(state: int, permutation: tuple[int, ...]) -> int:
    result = 0
    for position, destination in enumerate(permutation):
        result |= ((state >> position) & 1) << destination
    return result


@lru_cache(maxsize=128)
def _present_round_keys(key: bytes) -> tuple[int, ...]:
    key_size = len(key) * 8
    register = int.from_bytes(key, "big")
    mask = (1 << key_size) - 1
    keys: list[int] = []
    for round_number in range(1, 33):
        keys.append(register >> (key_size - 64))
        register = ((register << 61) | (register >> (key_size - 61))) & mask
        if key_size == 80:
            register = (register & ((1 << 76) - 1)) | (_PRESENT_SBOX[register >> 76] << 76)
            register ^= round_number << 15
        else:
            top_byte = (register >> 120) & 0xFF
            substituted = (_PRESENT_SBOX[top_byte >> 4] << 4) | _PRESENT_SBOX[top_byte & 0xF]
            register = (register & ((1 << 120) - 1)) | (substituted << 120)
            register ^= round_number << 62
    return tuple(keys)


def _present_encrypt_block(block: bytes, key: bytes) -> bytes:
    state = int.from_bytes(block, "big")
    round_keys = _present_round_keys(key)
    for round_number in range(31):
        state ^= round_keys[round_number]
        state = _present_substitute(state, _PRESENT_SBOX)
        state = _present_permute(state, _PRESENT_PBOX)
    return (state ^ round_keys[31]).to_bytes(8, "big")


def _present_decrypt_block(block: bytes, key: bytes) -> bytes:
    state = int.from_bytes(block, "big") ^ _present_round_keys(key)[31]
    round_keys = _present_round_keys(key)
    for round_number in range(30, -1, -1):
        state = _present_permute(state, _PRESENT_PBOX_INVERSE)
        state = _present_substitute(state, _PRESENT_SBOX_INVERSE)
        state ^= round_keys[round_number]
    return state.to_bytes(8, "big")


def _present(value: Data, args: Args, *, decrypting: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    mode = str(arg(args, 2, "CBC"))
    input_format = str(arg(args, 3, "Hex" if decrypting else "Raw"))
    output_format = str(arg(args, 4, "Raw" if decrypting else "Hex"))
    padding = str(arg(args, 5, "PKCS5"))
    if len(key) not in {10, 16}:
        raise ValueError("PRESENT requires a 10-byte or 16-byte key")
    if mode not in {"ECB", "CBC"}:
        raise ValueError("PRESENT supports ECB and CBC modes")
    if mode == "CBC" and len(iv) != 8:
        raise ValueError("PRESENT requires an 8-byte IV in CBC mode")
    data = _formatted_input(value, input_format)
    result = (
        _decrypt_mode(
            data,
            key,
            iv,
            mode,
            padding,
            _present_encrypt_block,
            _present_decrypt_block,
        )
        if decrypting
        else _encrypt_mode(data, key, iv, mode, padding, _present_encrypt_block)
    )
    return _formatted_output(result, output_format)


@implementation("PRESENT Encrypt", category="Ciphers")
def present_encrypt(value: Data, args: Args) -> Data:
    return _present(value, args, decrypting=False)


@implementation("PRESENT Decrypt", category="Ciphers")
def present_decrypt(value: Data, args: Args) -> Data:
    return _present(value, args, decrypting=True)


def _ciphersaber(data: bytes, iv: bytes, key: bytes, rounds: int) -> bytes:
    combined = key + iv
    state = list(range(256))
    right = 0
    for _ in range(rounds):
        for left in range(256):
            right = (right + state[left] + combined[left % len(combined)]) % 256
            state[left], state[right] = state[right], state[left]
    output = bytearray()
    left = right = 0
    for byte in data:
        left = (left + 1) % 256
        right = (right + state[left]) % 256
        state[left], state[right] = state[right], state[left]
        output.append(byte ^ state[(state[left] + state[right]) % 256])
    return bytes(output)


@implementation("CipherSaber2 Encrypt", category="Ciphers")
def ciphersaber_encrypt(value: Data, args: Args) -> bytes:
    key = _toggle_bytes(arg(args, 0, {"option": "Latin1", "string": ""}))
    rounds = require_int(arg(args, 1, 20), name="rounds")
    iv = secrets.token_bytes(10)
    return iv + _ciphersaber(to_bytes(value), iv, key, rounds)


@implementation("CipherSaber2 Decrypt", category="Ciphers")
def ciphersaber_decrypt(value: Data, args: Args) -> bytes:
    data = to_bytes(value)
    if len(data) < 10:
        raise ValueError("CipherSaber2 input must contain a 10-byte IV")
    key = _toggle_bytes(arg(args, 0, {"option": "Latin1", "string": ""}))
    rounds = require_int(arg(args, 1, 20), name="rounds")
    return _ciphersaber(data[10:], data[:10], key, rounds)


@implementation("RC4 Drop", category="Ciphers")
def rc4_drop(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    input_format = str(arg(args, 1, "Latin1"))
    output_format = str(arg(args, 2, "Hex"))
    drop = require_int(arg(args, 3, 192), name="drop") * 4
    if not key:
        raise ValueError("key must not be empty")
    if drop < 0:
        raise ValueError("drop must not be negative")
    state = list(range(256))
    right = 0
    for left in range(256):
        right = (right + state[left] + key[left % len(key)]) % 256
        state[left], state[right] = state[right], state[left]
    left = right = 0
    for _ in range(drop):
        left = (left + 1) % 256
        right = (right + state[left]) % 256
        state[left], state[right] = state[right], state[left]
    output = bytearray()
    for byte in _formatted_input(value, input_format):
        left = (left + 1) % 256
        right = (right + state[left]) % 256
        state[left], state[right] = state[right], state[left]
        output.append(byte ^ state[(state[left] + state[right]) % 256])
    return _formatted_output(bytes(output), output_format)
