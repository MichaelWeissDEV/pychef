"""Dedicated entry point for the SQL Minify operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import code_minify as _implementation

NAME = "SQL Minify"
CATEGORY = "Code"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
