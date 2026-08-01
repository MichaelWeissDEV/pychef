"""Dedicated entry point for the Generic Code Beautify operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import generic_beautify as _implementation

NAME = "Generic Code Beautify"
CATEGORY = "Code"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
