"""Dedicated entry point for the Extended GCD operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import extended_gcd as _implementation

NAME = "Extended GCD"
CATEGORY = "Arithmetic"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
