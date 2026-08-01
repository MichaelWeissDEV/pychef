"""Dedicated entry point for the Pseudo-Random Number Generator operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import random_bytes as _implementation

NAME = "Pseudo-Random Number Generator"
CATEGORY = "Generators"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
