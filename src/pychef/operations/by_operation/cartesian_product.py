"""Dedicated entry point for the Cartesian Product operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import cartesian_product as _implementation

NAME = "Cartesian Product"
CATEGORY = "Sets"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
