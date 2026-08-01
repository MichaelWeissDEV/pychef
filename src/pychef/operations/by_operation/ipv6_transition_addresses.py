"""Dedicated entry point for the IPv6 Transition Addresses operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..utility_extra import ipv6_transition as _implementation

NAME = "IPv6 Transition Addresses"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
