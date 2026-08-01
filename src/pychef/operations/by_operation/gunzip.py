"""Dedicated entry point for the Gunzip operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..compression import gunzip as _implementation

NAME = "Gunzip"
CATEGORY = "Compression"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
