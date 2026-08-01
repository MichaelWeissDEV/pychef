"""Dedicated entry point for the Alternating Caps operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import alternating_caps as _implementation

NAME = "Alternating Caps"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
