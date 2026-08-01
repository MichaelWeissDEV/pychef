"""Dedicated entry point for the Parse TCP operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import parse_tcp as _implementation

NAME = "Parse TCP"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
