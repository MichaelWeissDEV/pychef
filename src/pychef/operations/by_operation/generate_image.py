"""Dedicated entry point for the Generate Image operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..image_ops import generate_image as _implementation

NAME = "Generate Image"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
