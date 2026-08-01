"""Dedicated entry point for the JPath expression operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats import jpath as _implementation

NAME = "JPath expression"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
