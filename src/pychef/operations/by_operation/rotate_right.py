"""Dedicated entry point for the Rotate right operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import rotate_right as _implementation

NAME = "Rotate right"
CATEGORY = "Bitwise"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
