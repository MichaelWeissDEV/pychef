"""Dedicated entry point for the Find / Replace operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import find_replace as _implementation

NAME = "Find / Replace"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
