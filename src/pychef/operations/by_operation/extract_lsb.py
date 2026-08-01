"""Dedicated entry point for the Extract LSB operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..image_ops import extract_lsb as _implementation

NAME = "Extract LSB"
CATEGORY = "Image"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
