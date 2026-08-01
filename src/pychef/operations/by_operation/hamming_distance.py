"""Dedicated entry point for the Hamming Distance operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..hashing import hamming_distance as _implementation

NAME = "Hamming Distance"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
