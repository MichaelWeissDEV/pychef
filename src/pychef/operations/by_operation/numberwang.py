"""Dedicated entry point for the Numberwang operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import numberwang as _implementation

NAME = "Numberwang"
CATEGORY = "Miscellaneous"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
