"""Dedicated entry point for the Gzip operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..compression import gzip_compress as _implementation

NAME = "Gzip"
CATEGORY = "Compression"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
