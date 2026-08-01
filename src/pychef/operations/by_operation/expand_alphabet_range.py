"""Dedicated entry point for the Expand alphabet range operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import expand_alphabet_range as _implementation

NAME = "Expand alphabet range"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
