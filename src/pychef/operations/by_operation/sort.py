"""Dedicated entry point for the Sort operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import sort_items as _implementation

NAME = "Sort"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
