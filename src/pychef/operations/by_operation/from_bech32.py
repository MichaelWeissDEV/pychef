"""Dedicated entry point for the From Bech32 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..radix_extra import from_bech32 as _implementation

NAME = "From Bech32"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
