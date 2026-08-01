"""Dedicated entry point for the Standard Deviation operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import standard_deviation as _implementation

NAME = "Standard Deviation"
CATEGORY = "Arithmetic"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
