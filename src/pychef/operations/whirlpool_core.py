"""Pure-Python Whirlpool, Whirlpool-T, and Whirlpool-0 hashes.

The variant definitions follow the Whirlpool specification. The historical
S-box and table-generation method are ported from crypto-api (MIT license),
which is also CyberChef's reference implementation.
"""

from __future__ import annotations

import base64
from functools import reduce
from operator import xor

_MASK64 = 0xFFFFFFFFFFFFFFFF
_SBOX0 = tuple(
    base64.b64decode(
        b"aNDrK0idauTjo1aBffGFniyOeMoXqWHVXQuMPHdRIkI/VEGAzIazGC5XBmL0NtFrG2V1ENpJJvnLZue6rlBSqwXw"
        b"DXM7BCD+3fW0Xwq1wKBxpS1gcpM5CIMhXIex4ADDEpGKAhzmRcLE/b9EoUwzxYQjfLAlFTVp/5RNcKKvzdZst/gJ"
        b"82ek6uy21NIUHuEkOMbbS3o63l7flfyq184HDz1Ympic8qcRfotDA+Lc5bJOx23pJ0DYN5KPAR1TPlnBTzIW+nT7"
        b"Y580GipajcnP9pAoiJsxDr1K6JamDMh5vL7vbkaXW+0Z2ayZqClkH61VE7v3b7lHL+64e4kw0392gg=="
    )
)
_EBOX = (1, 11, 9, 12, 13, 6, 15, 3, 14, 8, 7, 4, 10, 2, 5, 0)
_RBOX = (7, 12, 11, 13, 14, 4, 9, 15, 6, 3, 8, 10, 2, 5, 1, 0)
_THETA = (1, 1, 4, 1, 8, 5, 2, 9)
_THETA0 = (1, 1, 3, 1, 5, 8, 9, 5)


def _latest_sbox() -> tuple[int, ...]:
    inverse = [0] * 16
    for index, value in enumerate(_EBOX):
        inverse[value] = index
    output: list[int] = []
    for value in range(256):
        left = _EBOX[value >> 4]
        right = inverse[value & 15]
        temporary = _RBOX[left ^ right]
        output.append((_EBOX[left ^ temporary] << 4) | inverse[right ^ temporary])
    return tuple(output)


_SBOX = _latest_sbox()


def _rotate_right(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (64 - amount))) & _MASK64


def _tables(
    sbox: tuple[int, ...], theta: tuple[int, ...]
) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    tables = [[0] * 256 for _ in range(8)]
    for index, substituted in enumerate(sbox):
        multiples = [0] * 10
        multiples[1] = substituted
        multiples[2] = substituted << 1
        if multiples[2] >= 0x100:
            multiples[2] ^= 0x11D
        multiples[3] = multiples[2] ^ substituted
        multiples[4] = multiples[2] << 1
        if multiples[4] >= 0x100:
            multiples[4] ^= 0x11D
        multiples[5] = multiples[4] ^ substituted
        multiples[8] = multiples[4] << 1
        if multiples[8] >= 0x100:
            multiples[8] ^= 0x11D
        multiples[9] = multiples[8] ^ substituted
        word = int.from_bytes(bytes(multiples[item] for item in theta), "big")
        for table_index in range(8):
            tables[table_index][index] = (
                _rotate_right(word, table_index * 8) if table_index else word
            )
    round_constants = [0] * 11
    for round_index in range(1, 11):
        start = 8 * (round_index - 1)
        round_constants[round_index] = sum(
            tables[table_index][start + table_index] & (0xFF << (56 - 8 * table_index))
            for table_index in range(8)
        )
    return tuple(tuple(table) for table in tables), tuple(round_constants)


_TABLES = {
    "Whirlpool": _tables(_SBOX, _THETA),
    "Whirlpool-T": _tables(_SBOX, _THETA0),
    "Whirlpool-0": _tables(_SBOX0, _THETA0),
}


def _transform(words: tuple[int, ...], tables: tuple[tuple[int, ...], ...]) -> list[int]:
    return [
        reduce(
            xor,
            (
                tables[table_index][
                    (words[(column - table_index) & 7] >> (56 - 8 * table_index)) & 0xFF
                ]
                for table_index in range(8)
            ),
            0,
        )
        & _MASK64
        for column in range(8)
    ]


def whirlpool(data: bytes, variant: str = "Whirlpool", rounds: int = 10) -> bytes:
    """Return a 512-bit Whirlpool-family digest."""
    if variant not in _TABLES:
        raise ValueError("Unknown Whirlpool version")
    if not 1 <= rounds <= 10:
        raise ValueError("Whirlpool rounds must be between 1 and 10")
    tables, round_constants = _TABLES[variant]
    bit_length = len(data) * 8
    zero_count = (32 - (len(data) + 1) % 64) % 64
    padded = data + b"\x80" + bytes(zero_count) + bit_length.to_bytes(32, "big")
    digest = [0] * 8
    for offset in range(0, len(padded), 64):
        block = tuple(
            int.from_bytes(padded[offset + index : offset + index + 8], "big")
            for index in range(0, 64, 8)
        )
        key = list(digest)
        state = [word ^ key_word for word, key_word in zip(block, key, strict=True)]
        for round_index in range(1, rounds + 1):
            key = _transform(tuple(key), tables)
            key[0] ^= round_constants[round_index]
            transformed = _transform(tuple(state), tables)
            state = [word ^ key_word for word, key_word in zip(transformed, key, strict=True)]
        digest = [
            old ^ encrypted ^ message
            for old, encrypted, message in zip(digest, state, block, strict=True)
        ]
    return b"".join(word.to_bytes(8, "big") for word in digest)


__all__ = ["whirlpool"]
