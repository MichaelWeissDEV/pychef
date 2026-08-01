"""Dedicated entry point for the Extract file paths operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import extract_file_paths as _implementation

NAME = "Extract file paths"
CATEGORY = "Extraction"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
