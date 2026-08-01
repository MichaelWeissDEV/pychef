"""Dedicated entry point for the Strip HTML tags operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import html_to_text as _implementation

NAME = "Strip HTML tags"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
