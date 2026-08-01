"""Dedicated entry point for the Scan for Embedded Files operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..remaining_formats import scan_for_embedded_files as _implementation

NAME = "Scan for Embedded Files"
CATEGORY = "Forensics"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
