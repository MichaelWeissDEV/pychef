"""Dedicated entry point for the From Morse Code operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import from_morse as _implementation

NAME = "From Morse Code"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
