"""Dedicated entry point for the Drop nth bytes operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import drop_nth_bytes as _implementation

NAME = "Drop nth bytes"
CATEGORY = "Data format"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
