"""Pure-Python RC2 compatible with CyberChef's node-forge implementation."""

from __future__ import annotations

from functools import lru_cache

from ..registry import operation
from ..types import Args, Data
from ._utils import arg
from .modern_ciphers import _formatted_input, _formatted_output, _toggle_bytes

_PI_TABLE = bytes.fromhex(
    "d978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2"
    "179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82"
    "54d66593ce60b21c7356c014a78cf1dc1275ca1f3bbee4d1423dd430a33cb626"
    "6fbf0eda4669075727f21d9bbc944303f811c7f690ef3ee706c3d52fc8661ed7"
    "08e8eade8052eef784aa72ac354d6a2a961ad2715a1549744b9fd05e0418a4ec"
    "c2e0416e0f51cbcc2491af50a1f47039997c3a8523b8b47afc02365b25559731"
    "2d5dfa98e38a92ae05df2910676cbac9d300e6cfe19ea82c6316013f58e289a9"
    "0d38341bab33ffb0bb480c5fb9b1cd2ec5f3db47e5a59c770aa62068fe7fc1ad"
)
_ROTATIONS = (1, 2, 3, 5)
_MASK = 0xFFFF


def _rotate_left(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (16 - amount))) & _MASK


def _rotate_right(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (16 - amount))) & _MASK


@lru_cache(maxsize=256)
def _expanded_key(key: bytes) -> tuple[int, ...]:
    if len(key) > 128:
        raise ValueError("RC2 keys cannot be longer than 128 bytes")
    if key:
        expanded = list(key)
        key_length = len(key)
        for index in range(key_length, 128):
            expanded.append(_PI_TABLE[(expanded[index - 1] + expanded[index - key_length]) & 0xFF])
    else:
        # node-forge permits an empty ByteBuffer. Its out-of-range reads are
        # coerced to zero, producing 128 repetitions of piTable[0].
        expanded = [_PI_TABLE[0]] * 128
    expanded[112] = _PI_TABLE[expanded[112]]
    for index in range(111, -1, -1):
        expanded[index] = _PI_TABLE[expanded[index + 1] ^ expanded[index + 16]]
    return tuple(expanded[index] | (expanded[index + 1] << 8) for index in range(0, 128, 2))


def _encrypt_block(block: bytes, key: bytes) -> bytes:
    words = [int.from_bytes(block[index : index + 2], "little") for index in range(0, 8, 2)]
    schedule = _expanded_key(key)
    schedule_index = 0
    for round_number in range(16):
        for index, rotation in enumerate(_ROTATIONS):
            words[index] = (
                words[index]
                + schedule[schedule_index]
                + (words[(index + 3) % 4] & words[(index + 2) % 4])
                + (~words[(index + 3) % 4] & words[(index + 1) % 4])
            ) & _MASK
            words[index] = _rotate_left(words[index], rotation)
            schedule_index += 1
        if round_number in {4, 10}:
            for index in range(4):
                words[index] = (words[index] + schedule[words[(index + 3) % 4] & 63]) & _MASK
    return b"".join(word.to_bytes(2, "little") for word in words)


def _decrypt_block(block: bytes, key: bytes) -> bytes:
    words = [int.from_bytes(block[index : index + 2], "little") for index in range(0, 8, 2)]
    schedule = _expanded_key(key)
    schedule_index = 63
    for round_number in range(15, -1, -1):
        for index in range(3, -1, -1):
            words[index] = _rotate_right(words[index], _ROTATIONS[index])
            words[index] = (
                words[index]
                - schedule[schedule_index]
                - (words[(index + 3) % 4] & words[(index + 2) % 4])
                - (~words[(index + 3) % 4] & words[(index + 1) % 4])
            ) & _MASK
            schedule_index -= 1
        if round_number in {11, 5}:
            for index in range(3, -1, -1):
                words[index] = (words[index] - schedule[words[(index + 3) % 4] & 63]) & _MASK
    return b"".join(word.to_bytes(2, "little") for word in words)


def _crypt(data: bytes, key: bytes, iv: bytes, *, decrypting: bool) -> bytes:
    if decrypting:
        if not data or len(data) % 8:
            raise ValueError("RC2 ciphertext must contain complete 8-byte blocks")
    else:
        padding = 8 - len(data) % 8
        data += bytes([padding]) * padding
    output = bytearray()
    feedback = iv
    for position in range(0, len(data), 8):
        block = data[position : position + 8]
        if decrypting:
            clear = _decrypt_block(block, key)
            output.extend(_xor(clear, feedback) if iv else clear)
            feedback = block
        else:
            cipher = _encrypt_block(_xor(block, feedback) if iv else block, key)
            output.extend(cipher)
            feedback = cipher
    result = bytes(output)
    if decrypting:
        padding = result[-1]
        if not 1 <= padding <= 8 or result[-padding:] != bytes([padding]) * padding:
            raise ValueError("invalid RC2 PKCS#7 padding")
        result = result[:-padding]
    return result


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _rc2(value: Data, args: Args, *, decrypting: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    if iv and len(iv) != 8:
        raise ValueError("RC2 requires an 8-byte IV for CBC mode")
    input_format = str(arg(args, 2, "Hex" if decrypting else "Raw"))
    output_format = str(arg(args, 3, "Raw" if decrypting else "Hex"))
    data = _formatted_input(value, input_format)
    return _formatted_output(_crypt(data, key, iv, decrypting=decrypting), output_format)


@operation("RC2 Encrypt", category="Ciphers")
def rc2_encrypt(value: Data, args: Args) -> Data:
    return _rc2(value, args, decrypting=False)


@operation("RC2 Decrypt", category="Ciphers")
def rc2_decrypt(value: Data, args: Args) -> Data:
    return _rc2(value, args, decrypting=True)
