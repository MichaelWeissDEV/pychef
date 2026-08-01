"""Dedicated entry point for the HAS-160 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..has160 import has160 as _implementation

NAME = "HAS-160"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
