"""Dedicated entry point for the Escape string operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import escape_string as _implementation

NAME = "Escape string"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
