"""Dedicated entry point for the SUB operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import subtract_bytes as _implementation

NAME = "SUB"
CATEGORY = "Bitwise"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
