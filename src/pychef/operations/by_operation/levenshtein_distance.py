"""Dedicated entry point for the Levenshtein Distance operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..maths import levenshtein_distance as _implementation

NAME = "Levenshtein Distance"
CATEGORY = "Arithmetic"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
