"""Cryptographically seeded probable-prime generation using Miller-Rabin."""

from __future__ import annotations

import secrets

from ..registry import operation
from ..types import Args, Data
from ._utils import arg, require_int


def _candidate(bits: int) -> int:
    return secrets.randbits(bits) | (1 << (bits - 1)) | 1


def _probable_prime(value: int, rounds: int) -> bool:
    if value < 2:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value == prime:
            return True
        if value % prime == 0:
            return False
    exponent = value - 1
    power = 0
    while exponent % 2 == 0:
        exponent //= 2
        power += 1
    for _ in range(rounds):
        witness = secrets.randbelow(value - 3) + 2
        result = pow(witness, exponent, value)
        if result in {1, value - 1}:
            continue
        for _ in range(power - 1):
            result = pow(result, 2, value)
            if result == value - 1:
                break
        else:
            return False
    return True


@operation("Pseudo-Random Prime Generator", category="Generators")
def pseudo_random_prime_generator(value: Data, args: Args) -> Data:
    del value
    bits = require_int(arg(args, 0, 512), name="bit length")
    crypto_grade = bool(arg(args, 1, False))
    output_format = str(arg(args, 2, "Decimal"))
    if bits < 2:
        raise ValueError("Bit length must be at least 2")
    if bits > 4096:
        raise ValueError("Bit length limited to 4096 bits for performance reasons")
    rounds = 40 if crypto_grade else 7
    for _ in range(10001):
        prime = _candidate(bits)
        if _probable_prime(prime, rounds):
            return f"0x{prime:x}" if output_format == "Hexadecimal" else str(prime)
    raise ValueError("Failed to generate prime after 10000 attempts. Try a different bit length.")
