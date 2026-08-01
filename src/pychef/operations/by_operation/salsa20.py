"""Dedicated entry point for the Salsa20 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..stream_ciphers import salsa20 as _implementation

NAME = "Salsa20"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
