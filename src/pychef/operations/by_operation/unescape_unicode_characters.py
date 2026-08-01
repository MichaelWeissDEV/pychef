"""Dedicated entry point for the Unescape Unicode Characters operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import unescape_unicode as _implementation

NAME = "Unescape Unicode Characters"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
