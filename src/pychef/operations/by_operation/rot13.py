"""Dedicated entry point for the ROT13 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import rot13 as _implementation

NAME = "ROT13"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
