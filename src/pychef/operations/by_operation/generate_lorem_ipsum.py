"""Dedicated entry point for the Generate Lorem Ipsum operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import lorem_ipsum as _implementation

NAME = "Generate Lorem Ipsum"
CATEGORY = "Generators"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
