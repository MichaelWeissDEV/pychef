"""Dedicated entry point for the SQL Beautify operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import sql_beautify as _implementation

NAME = "SQL Beautify"
CATEGORY = "Code"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
