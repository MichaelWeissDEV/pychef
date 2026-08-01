"""Dedicated entry point for the Parse Ethernet frame operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import parse_ethernet as _implementation

NAME = "Parse Ethernet frame"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
