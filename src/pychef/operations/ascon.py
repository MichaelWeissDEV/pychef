"""NIST SP 800-232 Ascon-AEAD128, Ascon-Hash256, and Ascon-Mac."""

from __future__ import annotations

import hmac

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg
from .modern_ciphers import _formatted_input, _formatted_output, _toggle_bytes

_MASK64 = 0xFFFFFFFFFFFFFFFF
_AEAD_RATE = 16
_AEAD_ERROR = (
    "Unable to decrypt: authentication failed. The ciphertext, key, nonce, or "
    "associated data may be incorrect or tampered with."
)


def _rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & _MASK64


def _permutation(state: list[int], rounds: int) -> None:
    for round_number in range(12 - rounds, 12):
        state[2] ^= 0xF0 - round_number * 0x10 + round_number
        state[0] ^= state[4]
        state[4] ^= state[3]
        state[2] ^= state[1]
        temporary = [((state[index] ^ _MASK64) & state[(index + 1) % 5]) for index in range(5)]
        for index in range(5):
            state[index] ^= temporary[(index + 1) % 5]
        state[1] ^= state[0]
        state[0] ^= state[4]
        state[3] ^= state[2]
        state[2] ^= _MASK64
        state[0] ^= _rotate_right(state[0], 19) ^ _rotate_right(state[0], 28)
        state[1] ^= _rotate_right(state[1], 61) ^ _rotate_right(state[1], 39)
        state[2] ^= _rotate_right(state[2], 1) ^ _rotate_right(state[2], 6)
        state[3] ^= _rotate_right(state[3], 10) ^ _rotate_right(state[3], 17)
        state[4] ^= _rotate_right(state[4], 7) ^ _rotate_right(state[4], 41)
        for index in range(5):
            state[index] &= _MASK64


def _load(data: bytes, position: int = 0) -> int:
    return int.from_bytes(data[position : position + 8], "little")


def _store(value: int) -> bytes:
    return (value & _MASK64).to_bytes(8, "little")


def _state(data: bytes) -> list[int]:
    if len(data) != 40:
        raise ValueError("Ascon states must be exactly 40 bytes")
    return [_load(data, position) for position in range(0, 40, 8)]


def _padded(data: bytes, rate: int) -> bytes:
    return data + b"\x01" + bytes(rate - len(data) % rate - 1)


def _initialize(key: bytes, nonce: bytes) -> list[int]:
    initialization = bytes((1, 0, 0x8C, 0x80, 0, _AEAD_RATE, 0, 0))
    state = _state(initialization + key + nonce)
    _permutation(state, 12)
    state[3] ^= _load(key)
    state[4] ^= _load(key, 8)
    return state


def _associated_data(state: list[int], associated_data: bytes) -> None:
    if associated_data:
        padded = _padded(associated_data, _AEAD_RATE)
        for position in range(0, len(padded), _AEAD_RATE):
            state[0] ^= _load(padded, position)
            state[1] ^= _load(padded, position + 8)
            _permutation(state, 8)
    state[4] ^= 1 << 63


def _encrypt_plaintext(state: list[int], plaintext: bytes) -> bytes:
    last_length = len(plaintext) % _AEAD_RATE
    message = _padded(plaintext, _AEAD_RATE)
    ciphertext = bytearray()
    for position in range(0, len(message) - _AEAD_RATE, _AEAD_RATE):
        state[0] ^= _load(message, position)
        state[1] ^= _load(message, position + 8)
        ciphertext.extend(_store(state[0]) + _store(state[1]))
        _permutation(state, 8)
    position = len(message) - _AEAD_RATE
    state[0] ^= _load(message, position)
    state[1] ^= _load(message, position + 8)
    ciphertext.extend((_store(state[0]) + _store(state[1]))[:last_length])
    return bytes(ciphertext)


def _decrypt_ciphertext(state: list[int], ciphertext: bytes) -> bytes:
    last_length = len(ciphertext) % _AEAD_RATE
    message = ciphertext + bytes(_AEAD_RATE - last_length)
    plaintext = bytearray()
    for position in range(0, len(message) - _AEAD_RATE, _AEAD_RATE):
        first = _load(message, position)
        second = _load(message, position + 8)
        plaintext.extend(_store(state[0] ^ first) + _store(state[1] ^ second))
        state[0], state[1] = first, second
        _permutation(state, 8)
    position = len(message) - _AEAD_RATE
    padded = bytes(last_length) + b"\x01" + bytes(_AEAD_RATE - last_length - 1)
    mask = bytes(last_length) + b"\xff" * (_AEAD_RATE - last_length)
    first = _load(message, position)
    second = _load(message, position + 8)
    last_plaintext = _store(state[0] ^ first) + _store(state[1] ^ second)
    state[0] = (state[0] & _load(mask)) ^ first ^ _load(padded)
    state[1] = (state[1] & _load(mask, 8)) ^ second ^ _load(padded, 8)
    plaintext.extend(last_plaintext[:last_length])
    return bytes(plaintext)


def _finalize(state: list[int], key: bytes) -> bytes:
    state[2] ^= _load(key)
    state[3] ^= _load(key, 8)
    _permutation(state, 12)
    state[3] ^= _load(key)
    state[4] ^= _load(key, 8)
    return _store(state[3]) + _store(state[4])


def _aead_encrypt(plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes) -> bytes:
    state = _initialize(key, nonce)
    _associated_data(state, associated_data)
    ciphertext = _encrypt_plaintext(state, plaintext)
    return ciphertext + _finalize(state, key)


def _aead_decrypt(
    ciphertext_and_tag: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
) -> bytes:
    if len(ciphertext_and_tag) < 16:
        raise ValueError(_AEAD_ERROR)
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    state = _initialize(key, nonce)
    _associated_data(state, associated_data)
    plaintext = _decrypt_ciphertext(state, ciphertext)
    if not hmac.compare_digest(_finalize(state, key), tag):
        raise ValueError(_AEAD_ERROR)
    return plaintext


def _validate_aead_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != 16:
        raise ValueError(
            f"Invalid key length: {len(key)} bytes.\n\n"
            "Ascon-AEAD128 requires a key of exactly 16 bytes (128 bits)."
        )
    if len(nonce) != 16:
        raise ValueError(
            f"Invalid nonce length: {len(nonce)} bytes.\n\n"
            "Ascon-AEAD128 requires a nonce of exactly 16 bytes (128 bits)."
        )


def _aead_operation(value: Data, args: Args, *, decrypting: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    nonce = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    associated_data = _toggle_bytes(arg(args, 2, {"option": "Hex", "string": ""}))
    _validate_aead_key_nonce(key, nonce)
    input_format = str(arg(args, 3, "Hex" if decrypting else "Raw"))
    output_format = str(arg(args, 4, "Raw" if decrypting else "Hex"))
    data = _formatted_input(value, input_format)
    result = (
        _aead_decrypt(data, key, nonce, associated_data)
        if decrypting
        else _aead_encrypt(data, key, nonce, associated_data)
    )
    return _formatted_output(result, output_format)


@implementation("Ascon Encrypt", category="Ciphers")
def ascon_encrypt(value: Data, args: Args) -> Data:
    return _aead_operation(value, args, decrypting=False)


@implementation("Ascon Decrypt", category="Ciphers")
def ascon_decrypt(value: Data, args: Args) -> Data:
    return _aead_operation(value, args, decrypting=True)


@implementation("Ascon Hash", category="Hashing")
def ascon_hash(value: Data, args: Args) -> Data:
    del args
    initialization = bytes((2, 0, 0xCC, 0, 1, 8, 0, 0))
    state = _state(initialization + bytes(32))
    _permutation(state, 12)
    message = _padded(to_bytes(value), 8)
    for position in range(0, len(message), 8):
        state[0] ^= _load(message, position)
        _permutation(state, 12)
    output = bytearray()
    while len(output) < 32:
        output.extend(_store(state[0]))
        _permutation(state, 12)
    return bytes(output[:32]).hex()


@implementation("Ascon MAC", category="Hashing")
def ascon_mac(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    if len(key) != 16:
        raise ValueError(
            f"Invalid key length: {len(key)} bytes.\n\n"
            "Ascon-Mac requires a key of exactly 16 bytes (128 bits)."
        )
    state = [0x0010200080CC0005, _load(key), _load(key, 8), 0, 0]
    _permutation(state, 12)
    message = to_bytes(value)
    position = 0
    word_index = 0
    while position + 8 <= len(message):
        state[word_index] ^= _load(message, position)
        word_index += 1
        if word_index == 4:
            word_index = 0
            _permutation(state, 12)
        position += 8
    remaining = message[position:]
    if remaining:
        state[word_index] ^= int.from_bytes(remaining, "little")
    state[word_index] ^= 1 << (8 * len(remaining))
    state[4] ^= 1 << 63
    _permutation(state, 12)
    return (_store(state[0]) + _store(state[1])).hex()
