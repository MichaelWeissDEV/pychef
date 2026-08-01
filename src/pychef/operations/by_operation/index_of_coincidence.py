"""Dedicated entry point for the Index of Coincidence operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..hashing import index_of_coincidence as _implementation

NAME = "Index of Coincidence"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
