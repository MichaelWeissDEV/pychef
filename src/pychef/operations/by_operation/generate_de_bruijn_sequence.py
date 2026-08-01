"""Dedicated entry point for the Generate De Bruijn Sequence operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import de_bruijn as _implementation

NAME = "Generate De Bruijn Sequence"
CATEGORY = "Generators"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
