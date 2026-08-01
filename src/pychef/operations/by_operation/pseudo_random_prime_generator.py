"""Dedicated entry point for the Pseudo-Random Prime Generator operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..random_prime import pseudo_random_prime_generator as _implementation

NAME = "Pseudo-Random Prime Generator"
CATEGORY = "Generators"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
