"""Dedicated entry point for the Symmetric Difference operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import symmetric_difference as _implementation

NAME = "Symmetric Difference"
CATEGORY = "Sets"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
