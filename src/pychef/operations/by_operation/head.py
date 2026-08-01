"""Dedicated entry point for the Head operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import head as _implementation

NAME = "Head"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
