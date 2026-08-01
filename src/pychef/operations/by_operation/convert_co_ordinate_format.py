"""Dedicated entry point for the Convert co-ordinate format operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..presentation import convert_coordinate_format as _implementation

NAME = "Convert co-ordinate format"
CATEGORY = "Geography"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
