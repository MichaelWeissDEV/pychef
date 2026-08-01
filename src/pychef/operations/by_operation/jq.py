"""Dedicated entry point for the Jq operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..code_queries import jq as _implementation

NAME = "Jq"
CATEGORY = "Code"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
