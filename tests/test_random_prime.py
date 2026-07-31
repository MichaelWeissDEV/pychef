"""Pseudo-random prime generator option and safety tests."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    divisor = 2
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 1
    return True


@pytest.mark.parametrize(("bits", "crypto_grade"), [(2, False), (16, False), (24, True)])
def test_random_prime_decimal_options(bits: int, crypto_grade: bool) -> None:
    result = bake(
        "ignored",
        [{"op": "Pseudo-Random Prime Generator", "args": [bits, crypto_grade, "Decimal"]}],
    )
    assert isinstance(result, str)
    prime = int(result)
    assert prime.bit_length() == bits
    assert _is_prime(prime)


def test_random_prime_hexadecimal_output() -> None:
    result = bake(
        "",
        [{"op": "Pseudo-Random Prime Generator", "args": [20, False, "Hexadecimal"]}],
    )
    assert isinstance(result, str) and result.startswith("0x")
    assert int(result, 16).bit_length() == 20


@pytest.mark.parametrize(
    ("bits", "message"),
    [(1, "at least 2"), (4097, "limited to 4096"), (2.5, "must be an integer")],
)
def test_random_prime_validates_bit_length(bits: float, message: str) -> None:
    with pytest.raises(OperationError, match=message):
        bake("", [{"op": "Pseudo-Random Prime Generator", "args": [bits, False, "Decimal"]}])
