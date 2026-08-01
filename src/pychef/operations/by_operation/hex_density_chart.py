"""Dedicated entry point for the Hex Density chart operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..presentation import hex_density_chart as _implementation

NAME = "Hex Density chart"
CATEGORY = "Visualisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
