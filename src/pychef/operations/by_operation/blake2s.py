"""Dedicated entry point for the BLAKE2s operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..hashing import blake2s as _implementation

NAME = "BLAKE2s"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
