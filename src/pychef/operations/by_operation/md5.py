"""Dedicated entry point for the MD5 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..hashing import md5 as _implementation

NAME = "MD5"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
