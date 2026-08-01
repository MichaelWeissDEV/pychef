"""Dedicated entry point for the MIME Decoding operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import mime_decoding as _implementation

NAME = "MIME Decoding"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
