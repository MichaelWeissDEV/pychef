"""Dedicated entry point for the Keccak operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..keccak import keccak as _implementation

NAME = "Keccak"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
