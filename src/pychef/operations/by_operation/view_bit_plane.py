"""Dedicated entry point for the View Bit Plane operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..image_ops import view_bit_plane as _implementation

NAME = "View Bit Plane"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
