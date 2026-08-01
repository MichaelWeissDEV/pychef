"""Dedicated entry point for the Fletcher-32 Checksum operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..hashing import fletcher32 as _implementation

NAME = "Fletcher-32 Checksum"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
