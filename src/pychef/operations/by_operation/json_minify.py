"""Dedicated entry point for the JSON Minify operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats import json_minify as _implementation

NAME = "JSON Minify"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
