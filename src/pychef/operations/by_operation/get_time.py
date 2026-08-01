"""Dedicated entry point for the Get Time operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..datetime_ops import get_time as _implementation

NAME = "Get Time"
CATEGORY = "Date / Time"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
