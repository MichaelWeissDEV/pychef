"""Dedicated entry point for the From Punycode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..encoding import from_punycode as _implementation

NAME = "From Punycode"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
