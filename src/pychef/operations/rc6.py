"""Pure-Python RC6 with configurable word size, rounds, and block mode."""

from __future__ import annotations

import math
import secrets
from functools import lru_cache

from ..registry import implementation
from ..types import Args, Data
from ._utils import arg, require_int
from .modern_ciphers import _formatted_input, _formatted_output, _toggle_bytes

_P256 = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
_Q256 = 0x9E3779B97F4A7C15F39CC0605CEDC8341082276BF3A27251F86C6A11D0C18E95


def _rotate_left(value: int, amount: int, word_size: int, rotation_mask: int) -> int:
    mask = (1 << word_size) - 1
    shift = (amount & rotation_mask) % word_size
    return ((value << shift) | (value >> (word_size - shift))) & mask


def _rotate_right(value: int, amount: int, word_size: int, rotation_mask: int) -> int:
    mask = (1 << word_size) - 1
    shift = (amount & rotation_mask) % word_size
    return ((value >> shift) | (value << (word_size - shift))) & mask


def _words(data: bytes, word_size: int) -> list[int]:
    width = word_size // 8
    return [
        int.from_bytes(data[position : position + width], "little")
        for position in range(0, len(data), width)
    ]


def _bytes(words: list[int] | tuple[int, ...], word_size: int) -> bytes:
    width = word_size // 8
    return b"".join(word.to_bytes(width, "little") for word in words)


@lru_cache(maxsize=256)
def _subkeys(key: bytes, rounds: int, word_size: int) -> tuple[int, ...]:
    width = word_size // 8
    word_count = max(math.ceil(len(key) / width), 1)
    key_words = _words(key.ljust(word_count * width, b"\0"), word_size)
    subkey_count = 2 * rounds + 4
    mask = (1 << word_size) - 1
    p_value = (_P256 >> (256 - word_size)) | 1
    q_value = (_Q256 >> (256 - word_size)) | 1
    rotation_mask = (1 << math.floor(math.log2(word_size))) - 1
    schedule = [p_value]
    for _position in range(1, subkey_count):
        schedule.append((schedule[-1] + q_value) & mask)

    accumulator_a = accumulator_b = 0
    schedule_position = key_position = 0
    for _iteration in range(3 * max(word_count, subkey_count)):
        accumulator_a = schedule[schedule_position] = _rotate_left(
            (schedule[schedule_position] + accumulator_a + accumulator_b) & mask,
            3,
            word_size,
            rotation_mask,
        )
        accumulator_b = key_words[key_position] = _rotate_left(
            (key_words[key_position] + accumulator_a + accumulator_b) & mask,
            accumulator_a + accumulator_b,
            word_size,
            rotation_mask,
        )
        schedule_position = (schedule_position + 1) % subkey_count
        key_position = (key_position + 1) % word_count
    return tuple(schedule)


def _encrypt_block(block: bytes, schedule: tuple[int, ...], rounds: int, word_size: int) -> bytes:
    word_a, word_b, word_c, word_d = _words(block, word_size)
    mask = (1 << word_size) - 1
    log_word_size = math.floor(math.log2(word_size))
    rotation_mask = (1 << log_word_size) - 1
    word_b = (word_b + schedule[0]) & mask
    word_d = (word_d + schedule[1]) & mask
    for round_number in range(1, rounds + 1):
        value_t = _rotate_left(
            (word_b * ((2 * word_b + 1) & mask)) & mask,
            log_word_size,
            word_size,
            rotation_mask,
        )
        value_u = _rotate_left(
            (word_d * ((2 * word_d + 1) & mask)) & mask,
            log_word_size,
            word_size,
            rotation_mask,
        )
        word_a = (
            _rotate_left(word_a ^ value_t, value_u, word_size, rotation_mask)
            + schedule[2 * round_number]
        ) & mask
        word_c = (
            _rotate_left(word_c ^ value_u, value_t, word_size, rotation_mask)
            + schedule[2 * round_number + 1]
        ) & mask
        word_a, word_b, word_c, word_d = word_b, word_c, word_d, word_a
    word_a = (word_a + schedule[2 * rounds + 2]) & mask
    word_c = (word_c + schedule[2 * rounds + 3]) & mask
    return _bytes((word_a, word_b, word_c, word_d), word_size)


def _decrypt_block(block: bytes, schedule: tuple[int, ...], rounds: int, word_size: int) -> bytes:
    word_a, word_b, word_c, word_d = _words(block, word_size)
    mask = (1 << word_size) - 1
    log_word_size = math.floor(math.log2(word_size))
    rotation_mask = (1 << log_word_size) - 1
    word_c = (word_c - schedule[2 * rounds + 3]) & mask
    word_a = (word_a - schedule[2 * rounds + 2]) & mask
    for round_number in range(rounds, 0, -1):
        word_a, word_b, word_c, word_d = word_d, word_a, word_b, word_c
        value_u = _rotate_left(
            (word_d * ((2 * word_d + 1) & mask)) & mask,
            log_word_size,
            word_size,
            rotation_mask,
        )
        value_t = _rotate_left(
            (word_b * ((2 * word_b + 1) & mask)) & mask,
            log_word_size,
            word_size,
            rotation_mask,
        )
        word_c = (
            _rotate_right(
                (word_c - schedule[2 * round_number + 1]) & mask,
                value_t,
                word_size,
                rotation_mask,
            )
            ^ value_u
        )
        word_a = (
            _rotate_right(
                (word_a - schedule[2 * round_number]) & mask,
                value_u,
                word_size,
                rotation_mask,
            )
            ^ value_t
        )
    word_d = (word_d - schedule[1]) & mask
    word_b = (word_b - schedule[0]) & mask
    return _bytes((word_a, word_b, word_c, word_d), word_size)


def _pad(data: bytes, padding: str, block_size: int) -> bytes:
    remainder = len(data) % block_size
    count = block_size - remainder if remainder else (block_size if padding == "PKCS5" else 0)
    if not count:
        return data
    if padding == "NO":
        raise ValueError(f"input is not a {block_size}-byte multiple")
    if padding == "PKCS5":
        return data + bytes([count]) * count
    if padding == "ZERO":
        return data + bytes(count)
    if padding == "RANDOM":
        return data + secrets.token_bytes(count)
    if padding == "BIT":
        return data + b"\x80" + bytes(count - 1)
    raise ValueError(f"unknown padding type: {padding}")


def _unpad(data: bytes, padding: str, block_size: int) -> bytes:
    if not data or padding in {"NO", "ZERO", "RANDOM"}:
        return data
    if padding == "PKCS5":
        count = data[-1]
        if not 1 <= count <= block_size or data[-count:] != bytes([count]) * count:
            raise ValueError("invalid PKCS#5 padding")
        return data[:-count]
    if padding == "BIT":
        stripped = data.rstrip(b"\0")
        if not stripped or stripped[-1] != 0x80:
            raise ValueError("invalid BIT padding")
        return stripped[:-1]
    raise ValueError(f"unknown padding type: {padding}")


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _crypt(
    data: bytes,
    key: bytes,
    iv: bytes,
    mode: str,
    padding: str,
    rounds: int,
    word_size: int,
    *,
    decrypting: bool,
) -> bytes:
    block_size = word_size // 2
    if not data:
        return b""
    schedule = _subkeys(key, rounds, word_size)

    def encrypt(block: bytes) -> bytes:
        return _encrypt_block(block, schedule, rounds, word_size)

    def decrypt(block: bytes) -> bytes:
        return _decrypt_block(block, schedule, rounds, word_size)

    if mode in {"ECB", "CBC"}:
        if decrypting and len(data) % block_size:
            raise ValueError(f"ciphertext length must be a multiple of {block_size}")
        if not decrypting:
            data = _pad(data, padding, block_size)
    original_length = len(data)
    if mode not in {"ECB", "CBC"} and len(data) % block_size:
        data = data.ljust((len(data) + block_size - 1) // block_size * block_size, b"\0")

    output = bytearray()
    feedback = iv
    for position in range(0, len(data), block_size):
        block = data[position : position + block_size]
        if mode == "ECB":
            output.extend(decrypt(block) if decrypting else encrypt(block))
        elif mode == "CBC":
            if decrypting:
                output.extend(_xor(decrypt(block), feedback))
                feedback = block
            else:
                feedback = encrypt(_xor(block, feedback))
                output.extend(feedback)
        elif mode == "CFB":
            transformed = _xor(encrypt(feedback), block)
            output.extend(transformed)
            feedback = block if decrypting else transformed
        elif mode == "OFB":
            feedback = encrypt(feedback)
            output.extend(_xor(feedback, block))
        elif mode == "CTR":
            output.extend(_xor(encrypt(feedback), block))
            counter = (int.from_bytes(feedback, "little") + 1) % (1 << (block_size * 8))
            feedback = counter.to_bytes(block_size, "little")
        else:
            raise ValueError(f"invalid block cipher mode: {mode}")
    result = bytes(output[:original_length]) if mode not in {"ECB", "CBC"} else bytes(output)
    return _unpad(result, padding, block_size) if decrypting and mode in {"ECB", "CBC"} else result


def _rc6(value: Data, args: Args, *, decrypting: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    mode = str(arg(args, 2, "CBC"))
    input_format = str(arg(args, 3, "Hex" if decrypting else "Raw"))
    output_format = str(arg(args, 4, "Raw" if decrypting else "Hex"))
    padding = str(arg(args, 5, "PKCS5"))
    word_size = require_int(arg(args, 6, 32), name="word size")
    rounds = require_int(arg(args, 7, 20), name="rounds")
    if not 8 <= word_size <= 256 or word_size % 8:
        raise ValueError("word size must be a multiple of 8 between 8 and 256")
    if not 1 <= rounds <= 255:
        raise ValueError("rounds must be between 1 and 255")
    block_size = word_size // 2
    if not iv:
        iv = bytes(block_size)
    if mode != "ECB" and len(iv) != block_size:
        raise ValueError(f"RC6-{word_size} requires a {block_size}-byte IV")
    data = _formatted_input(value, input_format)
    result = _crypt(
        data,
        key,
        iv,
        mode,
        padding,
        rounds,
        word_size,
        decrypting=decrypting,
    )
    return _formatted_output(result, output_format)


@implementation("RC6 Encrypt", category="Ciphers")
def rc6_encrypt(value: Data, args: Args) -> Data:
    return _rc6(value, args, decrypting=False)


@implementation("RC6 Decrypt", category="Ciphers")
def rc6_decrypt(value: Data, args: Args) -> Data:
    return _rc6(value, args, decrypting=True)
