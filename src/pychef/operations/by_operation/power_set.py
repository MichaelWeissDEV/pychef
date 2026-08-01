"""Dedicated entry point for the Power Set operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import power_set as _implementation

NAME = "Power Set"
CATEGORY = "Sets"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
