"""Dedicated entry point for the Fuzzy Match operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import fuzzy_match as _implementation

NAME = "Fuzzy Match"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
