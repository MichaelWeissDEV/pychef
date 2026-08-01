"""Pure-Python Twofish block cipher.

This is a Python port of CyberChef's Apache-2.0 Twofish implementation and
follows the algorithm from the Twofish paper.  It intentionally contains only
the 128-bit block primitive; operation-level modes and padding live beside the
public PyChef operations.
"""

from __future__ import annotations

import struct
from functools import lru_cache

_MASK32 = 0xFFFFFFFF
_ROUNDS = 16

_Q_NIBBLES = (
    (
        (8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4),
        (14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13),
        (11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1),
        (13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10),
    ),
    (
        (2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5),
        (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8),
        (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15),
        (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10),
    ),
)

_RS = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)


def _ror4(value: int) -> int:
    return (value >> 1) | ((value & 1) << 3)


def _make_q(which: int) -> tuple[int, ...]:
    tables = _Q_NIBBLES[which]
    output: list[int] = []
    for value in range(256):
        a0, b0 = value >> 4, value & 15
        a1 = a0 ^ b0
        b1 = a0 ^ _ror4(b0) ^ ((a0 << 3) & 8)
        a2, b2 = tables[0][a1], tables[1][b1]
        a3 = a2 ^ b2
        b3 = a2 ^ _ror4(b2) ^ ((a2 << 3) & 8)
        a4, b4 = tables[2][a3], tables[3][b3]
        output.append((b4 << 4) | a4)
    return tuple(output)


_Q0 = _make_q(0)
_Q1 = _make_q(1)


def _gf_multiply(left: int, right: int, polynomial: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x100:
            left ^= polynomial
        right >>= 1
    return result & 0xFF


def _mds_multiply(value: int) -> int:
    b0, b1, b2, b3 = ((value >> shift) & 0xFF for shift in (0, 8, 16, 24))
    r0 = (
        b0
        ^ _gf_multiply(b1, 0xEF, 0x169)
        ^ _gf_multiply(b2, 0x5B, 0x169)
        ^ _gf_multiply(b3, 0x5B, 0x169)
    )
    r1 = (
        _gf_multiply(b0, 0x5B, 0x169)
        ^ _gf_multiply(b1, 0xEF, 0x169)
        ^ _gf_multiply(b2, 0xEF, 0x169)
        ^ b3
    )
    r2 = (
        _gf_multiply(b0, 0xEF, 0x169)
        ^ _gf_multiply(b1, 0x5B, 0x169)
        ^ b2
        ^ _gf_multiply(b3, 0xEF, 0x169)
    )
    r3 = (
        _gf_multiply(b0, 0xEF, 0x169)
        ^ b1
        ^ _gf_multiply(b2, 0xEF, 0x169)
        ^ _gf_multiply(b3, 0x5B, 0x169)
    )
    return (r3 << 24) | (r2 << 16) | (r1 << 8) | r0


def _rs_multiply(key_part: bytes) -> int:
    return sum(
        (
            sum(
                _gf_multiply(coefficient, byte, 0x14D)
                for coefficient, byte in zip(row, key_part, strict=True)
            )
            & 0xFF
        )
        << (row_index * 8)
        for row_index, row in enumerate(_RS)
    )


def _h(value: int, words: tuple[int, ...], count: int) -> int:
    y = [(value >> shift) & 0xFF for shift in (0, 8, 16, 24)]
    if count == 4:
        y[0] = _Q1[y[0]] ^ (words[3] & 0xFF)
        y[1] = _Q0[y[1]] ^ ((words[3] >> 8) & 0xFF)
        y[2] = _Q0[y[2]] ^ ((words[3] >> 16) & 0xFF)
        y[3] = _Q1[y[3]] ^ ((words[3] >> 24) & 0xFF)
    if count >= 3:
        y[0] = _Q1[y[0]] ^ (words[2] & 0xFF)
        y[1] = _Q1[y[1]] ^ ((words[2] >> 8) & 0xFF)
        y[2] = _Q0[y[2]] ^ ((words[2] >> 16) & 0xFF)
        y[3] = _Q0[y[3]] ^ ((words[2] >> 24) & 0xFF)
    y[0] = _Q0[_Q0[y[0]] ^ (words[1] & 0xFF)] ^ (words[0] & 0xFF)
    y[1] = _Q0[_Q1[y[1]] ^ ((words[1] >> 8) & 0xFF)] ^ ((words[0] >> 8) & 0xFF)
    y[2] = _Q1[_Q0[y[2]] ^ ((words[1] >> 16) & 0xFF)] ^ ((words[0] >> 16) & 0xFF)
    y[3] = _Q1[_Q1[y[3]] ^ ((words[1] >> 24) & 0xFF)] ^ ((words[0] >> 24) & 0xFF)
    y = [_Q1[y[0]], _Q0[y[1]], _Q1[y[2]], _Q0[y[3]]]
    return _mds_multiply(y[0] | (y[1] << 8) | (y[2] << 16) | (y[3] << 24))


def _rol(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & _MASK32


def _ror(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & _MASK32


@lru_cache(maxsize=128)
def _schedule(key: bytes) -> tuple[tuple[int, ...], tuple[int, ...], int]:
    if len(key) not in {16, 24, 32}:
        raise ValueError("Twofish key must contain 16, 24, or 32 bytes")
    count = len(key) // 8
    even = tuple(
        int.from_bytes(key[index : index + 4], "little") for index in range(0, len(key), 8)
    )
    odd = tuple(
        int.from_bytes(key[index + 4 : index + 8], "little") for index in range(0, len(key), 8)
    )
    sbox_keys = tuple(
        _rs_multiply(key[index : index + 8]) for index in range((count - 1) * 8, -1, -8)
    )
    subkeys: list[int] = []
    rho = 0x01010101
    for index in range(20):
        left = _h((2 * index * rho) & _MASK32, even, count)
        right = _rol(_h(((2 * index + 1) * rho) & _MASK32, odd, count), 8)
        subkeys.extend(((left + right) & _MASK32, _rol((left + 2 * right) & _MASK32, 9)))
    return tuple(subkeys), sbox_keys, count


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block using a 16-, 24-, or 32-byte key."""
    if len(block) != 16:
        raise ValueError("Twofish requires 16-byte blocks")
    subkeys, sbox_keys, count = _schedule(key)
    r0, r1, r2, r3 = struct.unpack("<4I", block)
    r0, r1, r2, r3 = (
        r0 ^ subkeys[0],
        r1 ^ subkeys[1],
        r2 ^ subkeys[2],
        r3 ^ subkeys[3],
    )
    for round_index in range(0, _ROUNDS, 2):
        t0, t1 = _h(r0, sbox_keys, count), _h(_rol(r1, 8), sbox_keys, count)
        r2 = _ror(r2 ^ ((t0 + t1 + subkeys[8 + 2 * round_index]) & _MASK32), 1)
        r3 = _rol(r3, 1) ^ ((t0 + 2 * t1 + subkeys[9 + 2 * round_index]) & _MASK32)
        t0, t1 = _h(r2, sbox_keys, count), _h(_rol(r3, 8), sbox_keys, count)
        r0 = _ror(r0 ^ ((t0 + t1 + subkeys[10 + 2 * round_index]) & _MASK32), 1)
        r1 = _rol(r1, 1) ^ ((t0 + 2 * t1 + subkeys[11 + 2 * round_index]) & _MASK32)
    return struct.pack(
        "<4I",
        (r2 ^ subkeys[4]) & _MASK32,
        (r3 ^ subkeys[5]) & _MASK32,
        (r0 ^ subkeys[6]) & _MASK32,
        (r1 ^ subkeys[7]) & _MASK32,
    )


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt one 16-byte block using a 16-, 24-, or 32-byte key."""
    if len(block) != 16:
        raise ValueError("Twofish requires 16-byte blocks")
    subkeys, sbox_keys, count = _schedule(key)
    r0, r1, r2, r3 = struct.unpack("<4I", block)
    r0, r1, r2, r3 = (
        r0 ^ subkeys[4],
        r1 ^ subkeys[5],
        r2 ^ subkeys[6],
        r3 ^ subkeys[7],
    )
    for round_index in range(_ROUNDS - 2, -1, -2):
        t0, t1 = _h(r0, sbox_keys, count), _h(_rol(r1, 8), sbox_keys, count)
        r2 = _rol(r2, 1) ^ ((t0 + t1 + subkeys[10 + 2 * round_index]) & _MASK32)
        r3 = _ror(r3 ^ ((t0 + 2 * t1 + subkeys[11 + 2 * round_index]) & _MASK32), 1)
        t0, t1 = _h(r2, sbox_keys, count), _h(_rol(r3, 8), sbox_keys, count)
        r0 = _rol(r0, 1) ^ ((t0 + t1 + subkeys[8 + 2 * round_index]) & _MASK32)
        r1 = _ror(r1 ^ ((t0 + 2 * t1 + subkeys[9 + 2 * round_index]) & _MASK32), 1)
    return struct.pack(
        "<4I",
        (r2 ^ subkeys[0]) & _MASK32,
        (r3 ^ subkeys[1]) & _MASK32,
        (r0 ^ subkeys[2]) & _MASK32,
        (r1 ^ subkeys[3]) & _MASK32,
    )


__all__ = ["decrypt_block", "encrypt_block"]
