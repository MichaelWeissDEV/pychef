"""Pure-Python MD6 hash implementation."""

from __future__ import annotations

import math

_MASK64 = 0xFFFFFFFFFFFFFFFF
_Q = (
    0x7311C2812425CFA0,
    0x6432286434AAC8E7,
    0xB60450E9EF68B7C1,
    0xE8FB23908D9F06F1,
    0xDD2E76CBA691E5BF,
    0x0CD0D63B2C30BC41,
    0x1F8CCF6823058F8A,
    0x54E5ED5B88E3775D,
    0x4AD12AAE0A6D6031,
    0x3E7F16BB88222E0D,
    0x8AF8671D3FB50C2C,
    0x995AD1178BD25C31,
    0xC878C1DD04C4B633,
    0x3B72066C7A1552AC,
    0x0D6F3522631EFFCB,
)
_SHIFTS = (17, 18, 21, 31, 67, 89)
_RIGHT = (10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12)
_LEFT = (11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9)
_S0 = 0x0123456789ABCDEF
_SM = 0x7311C2812425CFA0


def _words(data: bytes) -> list[int]:
    return [int.from_bytes(data[index : index + 8], "big") for index in range(0, len(data), 8)]


def _bytes(words: list[int]) -> bytes:
    return b"".join((word & _MASK64).to_bytes(8, "big") for word in words)


def _compress(initial: list[int], rounds: int) -> list[int]:
    state = _S0
    words = list(initial)
    position = 89
    for _ in range(rounds):
        for step in range(16):
            value = (
                state
                ^ words[position + step - _SHIFTS[5]]
                ^ words[position + step - _SHIFTS[0]]
                ^ (words[position + step - _SHIFTS[1]] & words[position + step - _SHIFTS[2]])
                ^ (words[position + step - _SHIFTS[3]] & words[position + step - _SHIFTS[4]])
            ) & _MASK64
            value ^= value >> _RIGHT[step]
            words.append((value ^ (value << _LEFT[step])) & _MASK64)
        state = (((state << 1) | (state >> 63)) ^ (state & _SM)) & _MASK64
        position += 16
    return words[-16:]


def _control_words(
    level: int,
    node_index: int,
    rounds: int,
    levels: int,
    final: int,
    padding_bits: int,
    key_length: int,
    digest_bits: int,
) -> tuple[int, int]:
    unique = ((level & 0xFF) << 56) | (node_index & 0x00FFFFFFFFFFFFFF)
    control = (
        ((rounds & 0xFFF) << 48)
        | ((levels & 0xFF) << 40)
        | ((final & 0xF) << 36)
        | ((padding_bits & 0xFFFF) << 20)
        | ((key_length & 0xFF) << 12)
        | (digest_bits & 0xFFF)
    )
    return unique, control


def _node(
    block: list[int],
    chaining: list[int],
    node_index: int,
    padding_bits: int,
    final: int,
    *,
    level: int,
    key_words: list[int],
    key_length: int,
    rounds: int,
    levels: int,
    digest_bits: int,
) -> list[int]:
    unique, control = _control_words(
        level,
        node_index,
        rounds,
        levels,
        final,
        padding_bits,
        key_length,
        digest_bits,
    )
    return _compress([*_Q, *key_words, unique, control, *chaining, *block], rounds)


def _parallel(
    message: bytes,
    *,
    level: int,
    key_words: list[int],
    key_length: int,
    rounds: int,
    levels: int,
    digest_bits: int,
) -> bytes:
    final = int(len(message) <= 512)
    padding_bits = 0
    if not message or len(message) % 512:
        amount = 512 - len(message) % 512
        message += bytes(amount)
        padding_bits = amount * 8
    output: list[int] = []
    blocks = [message[index : index + 512] for index in range(0, len(message), 512)]
    for index, block in enumerate(blocks):
        output.extend(
            _node(
                _words(block),
                [],
                index,
                padding_bits if index == len(blocks) - 1 else 0,
                final,
                level=level,
                key_words=key_words,
                key_length=key_length,
                rounds=rounds,
                levels=levels,
                digest_bits=digest_bits,
            )
        )
    return _bytes(output)


def _sequential(
    message: bytes,
    *,
    level: int,
    key_words: list[int],
    key_length: int,
    rounds: int,
    levels: int,
    digest_bits: int,
) -> bytes:
    padding_bits = 0
    if not message or len(message) % 384:
        amount = 384 - len(message) % 384
        message += bytes(amount)
        padding_bits = amount * 8
    blocks = [message[index : index + 384] for index in range(0, len(message), 384)]
    chaining = [0] * 16
    for index, block in enumerate(blocks):
        chaining = _node(
            _words(block),
            chaining,
            index,
            padding_bits if index == len(blocks) - 1 else 0,
            int(index == len(blocks) - 1),
            level=level,
            key_words=key_words,
            key_length=key_length,
            rounds=rounds,
            levels=levels,
            digest_bits=digest_bits,
        )
    return _bytes(chaining)


def md6(data: bytes, bits: int = 256, key: bytes = b"", levels: int = 64) -> bytes:
    """Return an MD6 digest with the requested bit length."""
    if not 1 <= bits <= 512:
        raise ValueError("MD6 size must be between 1 and 512")
    if levels < 0:
        raise ValueError("MD6 levels must not be negative")
    key = key[:64]
    key_length = len(key)
    key_words = _words(key.ljust(64, b"\0"))
    rounds = math.ceil(max(80 if key else 0, 40 + bits / 4))
    message = data
    level = 0
    while True:
        level += 1
        common = {
            "level": level,
            "key_words": key_words,
            "key_length": key_length,
            "rounds": rounds,
            "levels": levels,
            "digest_bits": bits,
        }
        message = _sequential(message, **common) if level > levels else _parallel(message, **common)
        if len(message) == 128:
            break
    length = (bits + 7) // 8
    digest = bytearray(message[-length:])
    if bits % 8:
        digest[-1] &= (0xFF << (8 - bits % 8)) & 0xFF
    return bytes(digest)


__all__ = ["md6"]
