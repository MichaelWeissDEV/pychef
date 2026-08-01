"""Dedicated entry point for the Convert speed operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..utility_extra import convert_speed as _implementation

NAME = "Convert speed"
CATEGORY = "Data format"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
