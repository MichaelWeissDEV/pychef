"""Dedicated entry point for the To Camel case operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import camel_case as _implementation

NAME = "To Camel case"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
