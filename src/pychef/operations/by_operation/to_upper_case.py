"""Dedicated entry point for the To Upper case operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import upper_case as _implementation

NAME = "To Upper case"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
