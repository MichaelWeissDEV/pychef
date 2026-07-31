"""Pure-Python implementation of the Korean HAS-160 hash function."""

from __future__ import annotations

from ..registry import operation
from ..types import Args, Data, to_bytes
from ._utils import arg, require_int

_MASK = 0xFFFFFFFF
_ROTATIONS = (5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13)
_WORD_ORDERS = (
    (18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15),
    (22, 3, 6, 9, 12, 23, 15, 2, 5, 8, 20, 11, 14, 1, 4, 21, 7, 10, 13, 0),
    (26, 12, 5, 14, 7, 27, 0, 9, 2, 11, 24, 4, 13, 6, 15, 25, 8, 1, 10, 3),
    (30, 7, 2, 13, 8, 31, 3, 14, 9, 4, 28, 15, 10, 5, 0, 29, 11, 6, 1, 12),
)
_CONSTANTS = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC)
_B_ROTATIONS = (10, 17, 25, 30)


def _rotate_left(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & _MASK


def _extend_words(words: list[int]) -> None:
    combinations = (
        ((0, 1, 2, 3), (4, 5, 6, 7), (8, 9, 10, 11), (12, 13, 14, 15)),
        ((3, 6, 9, 12), (2, 5, 8, 15), (1, 4, 11, 14), (0, 7, 10, 13)),
        ((5, 7, 12, 14), (0, 2, 9, 11), (4, 6, 13, 15), (1, 3, 8, 10)),
        ((2, 7, 8, 13), (3, 4, 9, 14), (0, 5, 10, 15), (1, 6, 11, 12)),
    )
    for group in combinations:
        words.extend(
            words[first] ^ words[second] ^ words[third] ^ words[fourth]
            for first, second, third, fourth in group
        )


def _function(group: int, second: int, third: int, fourth: int) -> int:
    if group == 0:
        return (second & third) | (~second & fourth)
    if group == 2:
        return third ^ (second | ~fourth)
    return second ^ third ^ fourth


def _digest(data: bytes, rounds: int) -> bytes:
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += bytes((56 - len(padded)) % 64) + bit_length.to_bytes(8, "little")
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for position in range(0, len(padded), 64):
        words = [
            int.from_bytes(padded[offset : offset + 4], "little")
            for offset in range(position, position + 64, 4)
        ]
        _extend_words(words)
        first, second, third, fourth, fifth = state
        for round_number in range(rounds):
            group, index = divmod(round_number, 20)
            temporary = (
                _rotate_left(first, _ROTATIONS[index])
                + _function(group, second, third, fourth)
                + fifth
                + words[_WORD_ORDERS[group][index]]
                + _CONSTANTS[group]
            ) & _MASK
            fifth = fourth
            fourth = third
            third = _rotate_left(second, _B_ROTATIONS[group])
            second = first
            first = temporary
        state = [
            (current + updated) & _MASK
            for current, updated in zip(state, (first, second, third, fourth, fifth), strict=True)
        ]
    return b"".join(word.to_bytes(4, "little") for word in state)


@operation("HAS-160", category="Crypto")
def has160(value: Data, args: Args) -> Data:
    rounds = require_int(arg(args, 0, 80), name="rounds")
    if not 1 <= rounds <= 80:
        raise ValueError("rounds must be between 1 and 80")
    return _digest(to_bytes(value), rounds).hex()
