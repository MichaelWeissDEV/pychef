"""Dedicated entry point for the ADD operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import add_bytes as _implementation

NAME = "ADD"
CATEGORY = "Bitwise"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
