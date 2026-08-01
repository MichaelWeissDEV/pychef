"""Dedicated entry point for the Raw Deflate operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..compression import raw_deflate as _implementation

NAME = "Raw Deflate"
CATEGORY = "Compression"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
