"""Dedicated entry point for the Offset checker operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import offset_checker as _implementation

NAME = "Offset checker"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
