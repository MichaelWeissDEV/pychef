"""Dedicated entry point for the Randomize Colour Palette operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..image_ops import randomize_colour_palette as _implementation

NAME = "Randomize Colour Palette"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
