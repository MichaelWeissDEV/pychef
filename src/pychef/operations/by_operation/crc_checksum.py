"""Dedicated entry point for the CRC Checksum operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..hashing import crc_checksum as _implementation

NAME = "CRC Checksum"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
