"""Dedicated entry point for the Get All Casings operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import get_all_casings as _implementation

NAME = "Get All Casings"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
