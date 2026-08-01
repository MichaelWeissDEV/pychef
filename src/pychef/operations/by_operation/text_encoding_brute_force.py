"""Dedicated entry point for the Text Encoding Brute Force operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text_encoding_brute_force import text_encoding_brute_force as _implementation

NAME = "Text Encoding Brute Force"
CATEGORY = "Encodings"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
