"""Dedicated entry point for the To Hex Content operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..encoding import to_hex_content as _implementation

NAME = "To Hex Content"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
