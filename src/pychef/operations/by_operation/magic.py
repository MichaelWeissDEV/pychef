"""Dedicated entry point for the Magic operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..flow_more import magic as _implementation

NAME = "Magic"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
