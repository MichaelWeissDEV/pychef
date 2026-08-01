"""Dedicated entry point for the Parse UDP operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import parse_udp as _implementation

NAME = "Parse UDP"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
