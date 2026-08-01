"""Dedicated entry point for the Bit shift right operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import bit_shift_right as _implementation

NAME = "Bit shift right"
CATEGORY = "Bitwise"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
