"""Dedicated entry point for the Dechunk HTTP response operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..text import dechunk_http_response as _implementation

NAME = "Dechunk HTTP response"
CATEGORY = "Text"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
