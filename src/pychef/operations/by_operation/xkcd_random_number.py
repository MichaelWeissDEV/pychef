"""Dedicated entry point for the XKCD Random Number operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import xkcd_random as _implementation

NAME = "XKCD Random Number"
CATEGORY = "Generators"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
