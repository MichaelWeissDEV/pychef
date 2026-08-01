"""Dedicated entry point for the To UNIX Timestamp operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..datetime_ops import to_unix_timestamp as _implementation

NAME = "To UNIX Timestamp"
CATEGORY = "Date / Time"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
