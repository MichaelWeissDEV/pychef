"""Dedicated entry point for the Raw Inflate operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..compression import raw_inflate as _implementation

NAME = "Raw Inflate"
CATEGORY = "Compression"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
