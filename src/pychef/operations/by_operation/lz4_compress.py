"""Dedicated entry point for the LZ4 Compress operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..lz_codecs import lz4_compress as _implementation

NAME = "LZ4 Compress"
CATEGORY = "Compression"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
