"""Dedicated entry point for the Merge operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..flow_more import _identity as _implementation

NAME = "Merge"
CATEGORY = "Flow control"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
