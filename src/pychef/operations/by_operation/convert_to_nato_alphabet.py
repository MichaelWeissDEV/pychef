"""Dedicated entry point for the Convert to NATO alphabet operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import nato_alphabet as _implementation

NAME = "Convert to NATO alphabet"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
