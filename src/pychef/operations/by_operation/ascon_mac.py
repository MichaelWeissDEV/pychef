"""Dedicated entry point for the Ascon MAC operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ascon import ascon_mac as _implementation

NAME = "Ascon MAC"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
