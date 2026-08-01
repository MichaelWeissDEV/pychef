"""Dedicated entry point for the Drop bytes operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import drop_bytes as _implementation

NAME = "Drop bytes"
CATEGORY = "Data format"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
