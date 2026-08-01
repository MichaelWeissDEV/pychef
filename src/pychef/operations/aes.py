"""Dependency-free AES modes, GCM authentication, and RFC 3394 key wrapping."""

from __future__ import annotations

import hmac
from functools import lru_cache

from ..registry import implementation
from ..types import Args, Data
from ._utils import arg, require_int
from .modern_ciphers import _formatted_input, _formatted_output, _toggle_bytes

_BLOCK_SIZE = 16
_KEY_LENGTHS = {16, 24, 32}
_DEFAULT_WRAP_IV = bytes.fromhex("a6a6a6a6a6a6a6a6")


def _multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def _power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _multiply(result, value)
        value = _multiply(value, value)
        exponent >>= 1
    return result


def _rotate_byte(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def _make_s_box() -> tuple[int, ...]:
    output = []
    for value in range(256):
        inverse = _power(value, 254) if value else 0
        output.append(
            inverse
            ^ _rotate_byte(inverse, 1)
            ^ _rotate_byte(inverse, 2)
            ^ _rotate_byte(inverse, 3)
            ^ _rotate_byte(inverse, 4)
            ^ 0x63
        )
    return tuple(output)


_S_BOX = _make_s_box()
_INVERSE_S_BOX = tuple(_S_BOX.index(value) for value in range(256))


def _substitute_word(word: int) -> int:
    return (
        (_S_BOX[(word >> 24) & 0xFF] << 24)
        | (_S_BOX[(word >> 16) & 0xFF] << 16)
        | (_S_BOX[(word >> 8) & 0xFF] << 8)
        | _S_BOX[word & 0xFF]
    )


@lru_cache(maxsize=256)
def _round_keys(key: bytes) -> tuple[bytes, ...]:
    if len(key) not in _KEY_LENGTHS:
        raise ValueError(f"invalid AES key length: {len(key)} bytes")
    key_words = len(key) // 4
    rounds = key_words + 6
    words = [
        int.from_bytes(key[position : position + 4], "big") for position in range(0, len(key), 4)
    ]
    round_constant = 1
    for index in range(key_words, 4 * (rounds + 1)):
        temporary = words[index - 1]
        if index % key_words == 0:
            temporary = _substitute_word(((temporary << 8) | (temporary >> 24)) & 0xFFFFFFFF)
            temporary ^= round_constant << 24
            round_constant = _multiply(round_constant, 2)
        elif key_words > 6 and index % key_words == 4:
            temporary = _substitute_word(temporary)
        words.append(words[index - key_words] ^ temporary)
    expanded = b"".join(word.to_bytes(4, "big") for word in words)
    return tuple(expanded[position : position + 16] for position in range(0, len(expanded), 16))


def _shift_rows(state: list[int], *, inverse: bool = False) -> list[int]:
    direction = -1 if inverse else 1
    return [
        state[4 * ((column + direction * row) % 4) + row] for column in range(4) for row in range(4)
    ]


def _mix_columns(state: list[int], *, inverse: bool = False) -> list[int]:
    matrix = (14, 11, 13, 9) if inverse else (2, 3, 1, 1)
    output = [0] * 16
    for column in range(4):
        values = state[4 * column : 4 * column + 4]
        for row in range(4):
            output[4 * column + row] = (
                _multiply(values[0], matrix[-row % 4])
                ^ _multiply(values[1], matrix[(1 - row) % 4])
                ^ _multiply(values[2], matrix[(2 - row) % 4])
                ^ _multiply(values[3], matrix[(3 - row) % 4])
            )
    return output


def _add_round_key(state: list[int], round_key: bytes) -> list[int]:
    return [value ^ key_byte for value, key_byte in zip(state, round_key, strict=True)]


def _encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != _BLOCK_SIZE:
        raise ValueError("AES blocks must be 16 bytes")
    round_keys = _round_keys(key)
    state = _add_round_key(list(block), round_keys[0])
    for round_key in round_keys[1:-1]:
        state = [_S_BOX[value] for value in state]
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_key)
    state = [_S_BOX[value] for value in state]
    state = _shift_rows(state)
    return bytes(_add_round_key(state, round_keys[-1]))


def _decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != _BLOCK_SIZE:
        raise ValueError("AES blocks must be 16 bytes")
    round_keys = _round_keys(key)
    state = _add_round_key(list(block), round_keys[-1])
    for round_key in reversed(round_keys[1:-1]):
        state = _shift_rows(state, inverse=True)
        state = [_INVERSE_S_BOX[value] for value in state]
        state = _add_round_key(state, round_key)
        state = _mix_columns(state, inverse=True)
    state = _shift_rows(state, inverse=True)
    state = [_INVERSE_S_BOX[value] for value in state]
    return bytes(_add_round_key(state, round_keys[0]))


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _pkcs7_pad(data: bytes) -> bytes:
    count = _BLOCK_SIZE - len(data) % _BLOCK_SIZE
    return data + bytes([count]) * count


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("invalid PKCS#7 padding")
    count = data[-1]
    if not 1 <= count <= _BLOCK_SIZE or data[-count:] != bytes([count]) * count:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-count]


def _increment_32(counter: bytes) -> bytes:
    value = (int.from_bytes(counter[-4:], "big") + 1) & 0xFFFFFFFF
    return counter[:-4] + value.to_bytes(4, "big")


def _block_mode(
    data: bytes,
    key: bytes,
    iv: bytes,
    mode: str,
    *,
    decrypting: bool,
    no_padding: bool,
) -> bytes:
    if mode in {"CBC", "ECB"}:
        if decrypting:
            if len(data) % _BLOCK_SIZE:
                raise ValueError("ciphertext length must be a multiple of 16 bytes")
        elif no_padding:
            if len(data) % _BLOCK_SIZE:
                raise ValueError("Input length must be a multiple of 16 bytes for NoPadding modes.")
        else:
            data = _pkcs7_pad(data)
    output = bytearray()
    feedback = iv
    for position in range(0, len(data), _BLOCK_SIZE):
        block = data[position : position + _BLOCK_SIZE]
        if mode == "ECB":
            output.extend(_decrypt_block(block, key) if decrypting else _encrypt_block(block, key))
        elif mode == "CBC":
            if decrypting:
                output.extend(_xor(_decrypt_block(block, key), feedback))
                feedback = block
            else:
                feedback = _encrypt_block(_xor(block, feedback), key)
                output.extend(feedback)
        elif mode == "CFB":
            stream = _encrypt_block(feedback, key)
            transformed = _xor(block, stream[: len(block)])
            output.extend(transformed)
            feedback = block if decrypting else transformed
        elif mode == "OFB":
            feedback = _encrypt_block(feedback, key)
            output.extend(_xor(block, feedback[: len(block)]))
        elif mode == "CTR":
            output.extend(_xor(block, _encrypt_block(feedback, key)[: len(block)]))
            feedback = _increment_32(feedback)
        else:
            raise ValueError(f"invalid AES mode: {mode}")
    result = bytes(output)
    if decrypting and mode in {"CBC", "ECB"} and not no_padding:
        return _pkcs7_unpad(result)
    return result


def _galois_multiply(left: int, right: int) -> int:
    result = 0
    value = left
    for bit in range(128):
        if right & (1 << (127 - bit)):
            result ^= value
        value = (value >> 1) ^ (0xE1000000000000000000000000000000 if value & 1 else 0)
    return result


def _ghash(hash_key: bytes, data: bytes) -> bytes:
    if len(data) % _BLOCK_SIZE:
        raise ValueError("GHASH input must contain complete blocks")
    accumulator = 0
    multiplier = int.from_bytes(hash_key, "big")
    for position in range(0, len(data), _BLOCK_SIZE):
        accumulator = _galois_multiply(
            accumulator ^ int.from_bytes(data[position : position + _BLOCK_SIZE], "big"),
            multiplier,
        )
    return accumulator.to_bytes(16, "big")


def _pad_block(data: bytes) -> bytes:
    return data + bytes((-len(data)) % _BLOCK_SIZE)


def _gcm_initial_counter(hash_key: bytes, iv: bytes) -> bytes:
    if len(iv) == 12:
        return iv + b"\0\0\0\1"
    length_block = b"\0" * 8 + (len(iv) * 8).to_bytes(8, "big")
    return _ghash(hash_key, _pad_block(iv) + length_block)


def _gcm(
    data: bytes,
    key: bytes,
    iv: bytes,
    aad: bytes,
    *,
    decrypting: bool,
    expected_tag: bytes = b"",
) -> tuple[bytes, bytes]:
    hash_key = _encrypt_block(bytes(16), key)
    initial_counter = _gcm_initial_counter(hash_key, iv)
    counter = initial_counter
    output = bytearray()
    for position in range(0, len(data), _BLOCK_SIZE):
        counter = _increment_32(counter)
        block = data[position : position + _BLOCK_SIZE]
        output.extend(_xor(block, _encrypt_block(counter, key)[: len(block)]))
    result = bytes(output)
    ciphertext = data if decrypting else result
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    authentication = _ghash(hash_key, _pad_block(aad) + _pad_block(ciphertext) + lengths)
    tag = _xor(_encrypt_block(initial_counter, key), authentication)
    if decrypting and (len(expected_tag) != 16 or not hmac.compare_digest(tag, expected_tag)):
        raise ValueError("Unable to decrypt input with these parameters.")
    return result, tag


def _require_key(key: bytes) -> None:
    if len(key) not in _KEY_LENGTHS:
        raise ValueError(
            f"Invalid key length: {len(key)} bytes\n\n"
            "The following algorithms will be used based on the size of the key:\n"
            "  16 bytes = AES-128\n"
            "  24 bytes = AES-192\n"
            "  32 bytes = AES-256"
        )


def _append_tag(output: Data, tag: bytes, output_format: str) -> Data:
    formatted_tag = _formatted_output(tag, output_format)
    if isinstance(output, bytes):
        assert isinstance(formatted_tag, bytes)
        return output + b"\n\nTag: " + formatted_tag
    assert isinstance(formatted_tag, str)
    return output + "\n\nTag: " + formatted_tag


@implementation("AES Encrypt", category="Ciphers")
def aes_encrypt(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    mode_arg = str(arg(args, 2, "CBC"))
    mode = mode_arg.split("/", 1)[0]
    no_padding = mode_arg.endswith("NoPadding")
    input_format = str(arg(args, 3, "Raw"))
    output_format = str(arg(args, 4, "Hex"))
    aad = _toggle_bytes(arg(args, 5, {"option": "Hex", "string": ""}))
    include_iv = str(arg(args, 6, "Off"))
    _require_key(key)
    data = _formatted_input(value, input_format)
    if mode == "GCM":
        result, tag = _gcm(data, key, iv, aad, decrypting=False)
    else:
        if mode != "ECB" and not iv:
            iv = bytes(16)
        if mode != "ECB" and len(iv) != 16:
            raise ValueError(f"AES-{mode} requires a 16-byte IV")
        result = _block_mode(data, key, iv, mode, decrypting=False, no_padding=no_padding)
        tag = b""
    if include_iv == "Prepend":
        result = iv + result
    elif include_iv == "Append":
        result += iv
    output = _formatted_output(result, output_format)
    return _append_tag(output, tag, output_format) if mode == "GCM" else output


@implementation("AES Decrypt", category="Ciphers")
def aes_decrypt(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    configured_iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    iv_length = require_int(arg(args, 2, 16), name="IV length")
    mode_arg = str(arg(args, 3, "CBC"))
    mode = mode_arg.split("/", 1)[0]
    no_padding = mode_arg.endswith("NoPadding")
    input_format = str(arg(args, 4, "Hex"))
    output_format = str(arg(args, 5, "Raw"))
    tag = _toggle_bytes(arg(args, 6, {"option": "Hex", "string": ""}))
    aad = _toggle_bytes(arg(args, 7, {"option": "Hex", "string": ""}))
    iv_source = str(arg(args, 8, "Off"))
    _require_key(key)
    data = _formatted_input(value, input_format)
    if iv_source != "Off":
        if iv_length < 0 or len(data) <= iv_length:
            raise ValueError(f"Input is too short to contain an IV of {iv_length} bytes.")
        if iv_source == "From start":
            iv, data = data[:iv_length], data[iv_length:]
        else:
            iv, data = data[-iv_length:], data[:-iv_length]
    else:
        iv = configured_iv
    if mode == "GCM":
        result, _actual_tag = _gcm(data, key, iv, aad, decrypting=True, expected_tag=tag)
    else:
        if mode != "ECB" and not iv:
            iv = bytes(16)
        if mode != "ECB" and len(iv) != 16:
            raise ValueError(f"AES-{mode} requires a 16-byte IV")
        result = _block_mode(data, key, iv, mode, decrypting=True, no_padding=no_padding)
    return _formatted_output(result, output_format)


def _wrap_arguments(args: Args) -> tuple[bytes, bytes, str, str]:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": _DEFAULT_WRAP_IV.hex()}))
    if len(key) not in _KEY_LENGTHS:
        raise ValueError(f"KEK must be either 16, 24, or 32 bytes (currently {len(key)} bytes)")
    if len(iv) != 8:
        raise ValueError(f"IV must be 8 bytes (currently {len(iv)} bytes)")
    return key, iv, str(arg(args, 2, "Hex")), str(arg(args, 3, "Hex"))


@implementation("AES Key Wrap", category="Ciphers")
def aes_key_wrap(value: Data, args: Args) -> Data:
    key, accumulator, input_format, output_format = _wrap_arguments(args)
    data = _formatted_input(value, input_format)
    if len(data) < 16 or len(data) % 8:
        raise ValueError(f"input must be 8n (n>=2) bytes (currently {len(data)} bytes)")
    blocks = [data[position : position + 8] for position in range(0, len(data), 8)]
    for round_number in range(6):
        for index in range(len(blocks)):
            encrypted = _encrypt_block(accumulator + blocks[index], key)
            counter = len(blocks) * round_number + index + 1
            accumulator = _xor(encrypted[:8], counter.to_bytes(8, "big"))
            blocks[index] = encrypted[8:]
    return _formatted_output(accumulator + b"".join(blocks), output_format)


@implementation("AES Key Unwrap", category="Ciphers")
def aes_key_unwrap(value: Data, args: Args) -> Data:
    key, expected_iv, input_format, output_format = _wrap_arguments(args)
    data = _formatted_input(value, input_format)
    if len(data) < 24 or len(data) % 8:
        raise ValueError(f"input must be 8n (n>=3) bytes (currently {len(data)} bytes)")
    accumulator = data[:8]
    blocks = [data[position : position + 8] for position in range(8, len(data), 8)]
    for round_number in range(5, -1, -1):
        for index in range(len(blocks) - 1, -1, -1):
            counter = len(blocks) * round_number + index + 1
            decrypted = _decrypt_block(
                _xor(accumulator, counter.to_bytes(8, "big")) + blocks[index], key
            )
            accumulator, blocks[index] = decrypted[:8], decrypted[8:]
    if not hmac.compare_digest(accumulator, expected_iv):
        raise ValueError("IV mismatch")
    return _formatted_output(b"".join(blocks), output_format)
