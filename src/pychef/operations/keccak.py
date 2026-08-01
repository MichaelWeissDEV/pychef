"""Dependency-free Keccak hash operation (the pre-SHA-3 padding variant)."""

from __future__ import annotations

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg, require_int

_MASK64 = (1 << 64) - 1
_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotate(value: int, distance: int) -> int:
    if not distance:
        return value
    return ((value << distance) | (value >> (64 - distance))) & _MASK64


def _permutation(state: list[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        differences = [columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= differences[x]

        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate(state[x + 5 * y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    moved[x + 5 * y] ^ ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y])
                ) & _MASK64
        state[0] ^= round_constant


def _keccak(data: bytes, bits: int) -> bytes:
    if bits not in {224, 256, 384, 512}:
        raise ValueError("Keccak size must be 224, 256, 384, or 512 bits")
    rate = (1600 - bits * 2) // 8
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\0" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for position in range(0, rate, 8):
            state[position // 8] ^= int.from_bytes(block[position : position + 8], "little")
        _permutation(state)

    output = bytearray()
    while len(output) < bits // 8:
        for position in range(0, rate, 8):
            output.extend(state[position // 8].to_bytes(8, "little"))
        if len(output) < bits // 8:
            _permutation(state)
    return bytes(output[: bits // 8])


@implementation("Keccak", category="Hashing")
def keccak(value: Data, args: Args) -> str:
    bits = require_int(arg(args, 0, 512), name="size")
    return _keccak(to_bytes(value), bits).hex()
