"""Dedicated entry point for the Extract EXIF operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..remaining_formats import extract_exif as _implementation

NAME = "Extract EXIF"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
