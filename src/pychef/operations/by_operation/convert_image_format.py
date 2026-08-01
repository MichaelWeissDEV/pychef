"""Dedicated entry point for the Convert Image Format operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..image_ops import convert_image_format as _implementation

NAME = "Convert Image Format"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
