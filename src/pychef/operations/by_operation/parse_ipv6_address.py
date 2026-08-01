"""Dedicated entry point for the Parse IPv6 address operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..network import parse_ipv6 as _implementation

NAME = "Parse IPv6 address"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
