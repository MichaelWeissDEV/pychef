"""Dependency-free Argon2 and bcrypt password hashing operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int
from .blowfish import _INITIAL_P, _INITIAL_S, _encrypt_pair
from .modern_ciphers import _toggle_bytes

_MASK64 = (1 << 64) - 1


def _blake2b_long(data: bytes, length: int) -> bytes:
    """Argon2's variable-length H' function."""
    if length <= 0 or length > 0xFFFFFFFF:
        raise ValueError("Argon2 hash length must be between 1 and 4294967295 bytes")
    prefixed = struct.pack("<I", length) + data
    if length <= 64:
        return hashlib.blake2b(prefixed, digest_size=length).digest()
    rounds = (length + 31) // 32 - 2
    value = hashlib.blake2b(prefixed, digest_size=64).digest()
    output = bytearray(value[:32])
    for _ in range(1, rounds):
        value = hashlib.blake2b(value, digest_size=64).digest()
        output.extend(value[:32])
    output.extend(hashlib.blake2b(value, digest_size=length - 32 * rounds).digest())
    return bytes(output)


def _rotate_right(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (64 - amount))) & _MASK64


def _blamka(left: int, right: int) -> int:
    return (left + right + 2 * (left & 0xFFFFFFFF) * (right & 0xFFFFFFFF)) & _MASK64


def _argon_g(words: list[int], a: int, b: int, c: int, d: int) -> None:
    words[a] = _blamka(words[a], words[b])
    words[d] = _rotate_right(words[d] ^ words[a], 32)
    words[c] = _blamka(words[c], words[d])
    words[b] = _rotate_right(words[b] ^ words[c], 24)
    words[a] = _blamka(words[a], words[b])
    words[d] = _rotate_right(words[d] ^ words[a], 16)
    words[c] = _blamka(words[c], words[d])
    words[b] = _rotate_right(words[b] ^ words[c], 63)


def _argon_round(words: list[int], indexes: list[int]) -> None:
    _argon_g(words, indexes[0], indexes[4], indexes[8], indexes[12])
    _argon_g(words, indexes[1], indexes[5], indexes[9], indexes[13])
    _argon_g(words, indexes[2], indexes[6], indexes[10], indexes[14])
    _argon_g(words, indexes[3], indexes[7], indexes[11], indexes[15])
    _argon_g(words, indexes[0], indexes[5], indexes[10], indexes[15])
    _argon_g(words, indexes[1], indexes[6], indexes[11], indexes[12])
    _argon_g(words, indexes[2], indexes[7], indexes[8], indexes[13])
    _argon_g(words, indexes[3], indexes[4], indexes[9], indexes[14])


def _argon_compress(
    previous: list[int], reference: list[int], old: list[int] | None = None
) -> list[int]:
    mixed = [left ^ right for left, right in zip(previous, reference, strict=True)]
    output = mixed.copy()
    if old is not None:
        output = [left ^ right for left, right in zip(output, old, strict=True)]
    transformed = mixed.copy()
    for row in range(8):
        _argon_round(transformed, list(range(row * 16, row * 16 + 16)))
    for column in range(8):
        indexes = [column * 2 + row * 16 + pair for row in range(8) for pair in (0, 1)]
        _argon_round(transformed, indexes)
    return [left ^ right for left, right in zip(output, transformed, strict=True)]


def _reference_index(
    pseudo_random: int,
    pass_number: int,
    slice_number: int,
    index: int,
    same_lane: bool,
    segment_length: int,
    lane_length: int,
) -> int:
    if pass_number == 0:
        if slice_number == 0:
            area = index - 1
        elif same_lane:
            area = slice_number * segment_length + index - 1
        else:
            area = slice_number * segment_length - (1 if index == 0 else 0)
        start = 0
    else:
        if same_lane:
            area = lane_length - segment_length + index - 1
        else:
            area = lane_length - segment_length - (1 if index == 0 else 0)
        start = ((slice_number + 1) * segment_length) % lane_length
    relative = pseudo_random & 0xFFFFFFFF
    relative = (relative * relative) >> 32
    relative = area - 1 - ((area * relative) >> 32)
    return (start + relative) % lane_length


def _argon2_hash(
    password: bytes,
    salt: bytes,
    iterations: int,
    memory: int,
    parallelism: int,
    length: int,
    variant: int,
) -> bytes:
    if len(salt) < 8:
        raise ValueError("Argon2 salt must be at least 8 bytes")
    if iterations < 1:
        raise ValueError("Argon2 iterations must be positive")
    if not 1 <= parallelism <= 0xFFFFFF:
        raise ValueError("Argon2 parallelism must be between 1 and 16777215")
    if memory < 8 * parallelism:
        raise ValueError("Argon2 memory must be at least eight times its parallelism")
    if variant not in {0, 1, 2}:
        raise ValueError("Invalid Argon2 type")
    segment_length = memory // (parallelism * 4)
    memory_blocks = segment_length * parallelism * 4
    lane_length = segment_length * 4
    header = b"".join(
        struct.pack("<I", item) for item in (parallelism, length, memory, iterations, 0x13, variant)
    )
    initial = hashlib.blake2b(
        header
        + struct.pack("<I", len(password))
        + password
        + struct.pack("<I", len(salt))
        + salt
        + b"\0\0\0\0"
        + b"\0\0\0\0",
        digest_size=64,
    ).digest()
    blocks: list[list[int]] = [[0] * 128 for _ in range(memory_blocks)]
    for lane in range(parallelism):
        for index in range(2):
            raw = _blake2b_long(initial + struct.pack("<II", index, lane), 1024)
            blocks[lane * lane_length + index] = list(struct.unpack("<128Q", raw))

    zero = [0] * 128
    for pass_number in range(iterations):
        for slice_number in range(4):
            for lane in range(parallelism):
                start_index = 2 if pass_number == 0 and slice_number == 0 else 0
                independent = variant == 1 or (
                    variant == 2 and pass_number == 0 and slice_number < 2
                )
                input_block = [0] * 128
                address_block = [0] * 128
                if independent:
                    input_block[:6] = [
                        pass_number,
                        lane,
                        slice_number,
                        memory_blocks,
                        iterations,
                        variant,
                    ]

                    def next_addresses(
                        input_words: list[int] = input_block,
                        address_words: list[int] = address_block,
                    ) -> None:
                        input_words[6] += 1
                        address_words[:] = _argon_compress(zero, _argon_compress(zero, input_words))

                    if start_index:
                        next_addresses()
                for index in range(start_index, segment_length):
                    current = lane * lane_length + slice_number * segment_length + index
                    previous = (
                        lane * lane_length + lane_length - 1
                        if current % lane_length == 0
                        else current - 1
                    )
                    if independent:
                        if index % 128 == 0:
                            next_addresses()
                        pseudo_random = address_block[index % 128]
                    else:
                        pseudo_random = blocks[previous][0]
                    reference_lane = (pseudo_random >> 32) % parallelism
                    if pass_number == 0 and slice_number == 0:
                        reference_lane = lane
                    reference_index = _reference_index(
                        pseudo_random,
                        pass_number,
                        slice_number,
                        index,
                        reference_lane == lane,
                        segment_length,
                        lane_length,
                    )
                    reference = reference_lane * lane_length + reference_index
                    old = blocks[current] if pass_number else None
                    blocks[current] = _argon_compress(blocks[previous], blocks[reference], old)

    final = blocks[lane_length - 1].copy()
    for lane in range(1, parallelism):
        final = [
            left ^ right
            for left, right in zip(final, blocks[(lane + 1) * lane_length - 1], strict=True)
        ]
    return _blake2b_long(struct.pack("<128Q", *final), length)


_ARGON_VARIANTS = {"Argon2d": 0, "Argon2i": 1, "Argon2id": 2}


@operation("Argon2", category="Crypto")
def argon2(value: Data, args: Args) -> Data:
    salt = _toggle_bytes(arg(args, 0, {"option": "UTF8", "string": "somesalt"}))
    iterations = require_int(arg(args, 1, 3), name="iterations")
    memory = require_int(arg(args, 2, 4096), name="memory")
    parallelism = require_int(arg(args, 3, 1), name="parallelism")
    length = require_int(arg(args, 4, 32), name="hash length")
    type_name = str(arg(args, 5, "Argon2i"))
    variant = _ARGON_VARIANTS.get(type_name)
    if variant is None:
        raise ValueError(f"Invalid Argon2 type: {type_name}")
    digest = _argon2_hash(to_bytes(value), salt, iterations, memory, parallelism, length, variant)
    output_format = str(arg(args, 6, "Encoded hash"))
    if output_format == "Hex hash":
        return digest.hex()
    if output_format == "Raw hash":
        return digest
    salt64 = base64.b64encode(salt).decode().rstrip("=")
    digest64 = base64.b64encode(digest).decode().rstrip("=")
    return (
        f"${type_name.lower()}$v=19$m={memory},t={iterations},p={parallelism}${salt64}${digest64}"
    )


_ARGON_RE = re.compile(
    r"^\$(argon2[idi]{1,2})\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)"
    r"\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$"
)


@operation("Argon2 compare", category="Crypto")
def argon2_compare(value: Data, args: Args) -> Data:
    encoded = str(arg(args, 0, ""))
    match = _ARGON_RE.fullmatch(encoded)
    if match is None or match.group(2) != "19":
        return "No match"
    try:
        variant = {"argon2d": 0, "argon2i": 1, "argon2id": 2}[match.group(1)]
        salt = base64.b64decode(match.group(6) + "=" * (-len(match.group(6)) % 4))
        expected = base64.b64decode(match.group(7) + "=" * (-len(match.group(7)) % 4))
        actual = _argon2_hash(
            to_bytes(value),
            salt,
            int(match.group(4)),
            int(match.group(3)),
            int(match.group(5)),
            len(expected),
            variant,
        )
    except (ValueError, KeyError):
        return "No match"
    return f"Match: {to_text(value)}" if hmac.compare_digest(actual, expected) else "No match"


_BCRYPT_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_BCRYPT_INDEX = {character: index for index, character in enumerate(_BCRYPT_ALPHABET)}
_BCRYPT_RE = re.compile(r"^\$(2[abxy])\$(\d{2})\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$")


def _bcrypt_b64encode(data: bytes, length: int) -> str:
    output = bytearray()
    offset = 0
    while offset < len(data) and len(output) < length:
        first = data[offset]
        offset += 1
        output.append(_BCRYPT_ALPHABET[first >> 2])
        first = (first & 3) << 4
        if offset >= len(data):
            output.append(_BCRYPT_ALPHABET[first])
            break
        second = data[offset]
        offset += 1
        first |= second >> 4
        output.append(_BCRYPT_ALPHABET[first])
        first = (second & 15) << 2
        if offset >= len(data):
            output.append(_BCRYPT_ALPHABET[first])
            break
        second = data[offset]
        offset += 1
        first |= second >> 6
        output.append(_BCRYPT_ALPHABET[first])
        output.append(_BCRYPT_ALPHABET[second & 63])
    return output[:length].decode()


def _bcrypt_b64decode(value: str, length: int) -> bytes:
    output = bytearray()
    offset = 0
    raw = value.encode()
    try:
        while offset < len(raw) - 1 and len(output) < length:
            first = _BCRYPT_INDEX[raw[offset]]
            second = _BCRYPT_INDEX[raw[offset + 1]]
            offset += 2
            output.append((first << 2) | ((second & 0x30) >> 4))
            if offset >= len(raw) or len(output) >= length:
                break
            first = _BCRYPT_INDEX[raw[offset]]
            offset += 1
            output.append(((second & 15) << 4) | ((first & 0x3C) >> 2))
            if offset >= len(raw) or len(output) >= length:
                break
            second = _BCRYPT_INDEX[raw[offset]]
            offset += 1
            output.append(((first & 3) << 6) | second)
    except KeyError as exc:
        raise ValueError("Invalid bcrypt base64") from exc
    if len(output) != length:
        raise ValueError("Invalid bcrypt base64 length")
    return bytes(output)


def _stream_word(data: bytes, offset: int) -> tuple[int, int]:
    word = 0
    for _ in range(4):
        word = (word << 8) | data[offset]
        offset = (offset + 1) % len(data)
    return word, offset


def _bcrypt_expand(
    p_array: list[int], boxes: tuple[list[int], ...], key: bytes, salt: bytes | None
) -> None:
    key_offset = 0
    for index in range(18):
        word, key_offset = _stream_word(key, key_offset)
        p_array[index] ^= word
    left = right = salt_offset = 0
    destinations = [p_array, *boxes]
    for destination in destinations:
        for index in range(0, len(destination), 2):
            if salt is not None:
                word, salt_offset = _stream_word(salt, salt_offset)
                left ^= word
                word, salt_offset = _stream_word(salt, salt_offset)
                right ^= word
            left, right = _encrypt_pair(left, right, p_array, boxes)
            destination[index], destination[index + 1] = left, right


def _bcrypt_hash(password: bytes, salt: bytes, cost: int) -> str:
    if not 4 <= cost <= 31:
        raise ValueError("bcrypt rounds must be between 4 and 31")
    if len(salt) != 16:
        raise ValueError("bcrypt salt must contain 16 bytes")
    key = (password + b"\0")[:72]
    if not key:
        key = b"\0"
    p_array = list(_INITIAL_P)
    boxes = tuple(list(box) for box in _INITIAL_S)
    _bcrypt_expand(p_array, boxes, key, salt)
    for _ in range(1 << cost):
        _bcrypt_expand(p_array, boxes, key, None)
        _bcrypt_expand(p_array, boxes, salt, None)
    ciphertext = bytearray(b"OrpheanBeholderScryDoubt")
    for offset in range(0, 24, 8):
        left, right = struct.unpack(">2I", ciphertext[offset : offset + 8])
        for _ in range(64):
            left, right = _encrypt_pair(left, right, p_array, boxes)
        ciphertext[offset : offset + 8] = struct.pack(">2I", left, right)
    return _bcrypt_b64encode(bytes(ciphertext[:23]), 31)


@operation("Bcrypt", category="Crypto")
def bcrypt(value: Data, args: Args) -> Data:
    cost = require_int(arg(args, 0, 10), name="rounds")
    salt = secrets.token_bytes(16)
    return (
        f"$2b${cost:02d}${_bcrypt_b64encode(salt, 22)}{_bcrypt_hash(to_bytes(value), salt, cost)}"
    )


@operation("Bcrypt compare", category="Crypto")
def bcrypt_compare(value: Data, args: Args) -> Data:
    encoded = str(arg(args, 0, ""))
    match = _BCRYPT_RE.fullmatch(encoded)
    if match is None:
        raise ValueError("Error: invalid hash provided")
    cost = int(match.group(2))
    if not 4 <= cost <= 31:
        raise ValueError("Error: invalid hash provided")
    salt = _bcrypt_b64decode(match.group(3), 16)
    actual = _bcrypt_hash(to_bytes(value), salt, cost)
    return f"Match: {to_text(value)}" if hmac.compare_digest(actual, match.group(4)) else "No match"
