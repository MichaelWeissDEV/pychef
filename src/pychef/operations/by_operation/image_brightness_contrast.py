"""Dedicated entry point for the Image Brightness / Contrast operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..image_ops import image_brightness_contrast as _implementation

NAME = "Image Brightness / Contrast"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
