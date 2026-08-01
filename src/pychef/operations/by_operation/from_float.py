"""Dedicated entry point for the From Float operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..encoding import from_float as _implementation

NAME = "From Float"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
