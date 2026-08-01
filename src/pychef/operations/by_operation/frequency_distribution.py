"""Dedicated entry point for the Frequency distribution operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import frequency_distribution as _implementation

NAME = "Frequency distribution"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
