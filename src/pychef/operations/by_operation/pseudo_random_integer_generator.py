"""Dedicated entry point for the Pseudo-Random Integer Generator operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import random_integers as _implementation

NAME = "Pseudo-Random Integer Generator"
CATEGORY = "Generators"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
