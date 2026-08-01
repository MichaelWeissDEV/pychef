"""Dedicated entry point for the Strip TCP header operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import strip_tcp as _implementation

NAME = "Strip TCP header"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
