"""Dedicated entry point for the To Charcode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..encoding import to_charcode as _implementation

NAME = "To Charcode"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
