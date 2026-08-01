"""Dedicated entry point for the Fang URL operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..network import fang_url as _implementation

NAME = "Fang URL"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
