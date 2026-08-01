"""Dedicated entry point for the Detect File Type operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..analysis_extra import detect_file_type as _implementation

NAME = "Detect File Type"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
