"""Dedicated entry point for the Add line numbers operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import add_line_numbers as _implementation

NAME = "Add line numbers"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
