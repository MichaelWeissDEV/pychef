"""Dedicated entry point for the Show on map operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..presentation import show_on_map as _implementation

NAME = "Show on map"
CATEGORY = "Geography"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
