"""Dedicated entry point for the Encode text operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text_encoding import encode_text as _implementation

NAME = "Encode text"
CATEGORY = "Encodings"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
