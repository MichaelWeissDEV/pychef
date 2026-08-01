"""Dedicated entry point for the Extract MAC addresses operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..network import extract_mac_addresses as _implementation

NAME = "Extract MAC addresses"
CATEGORY = "Networking"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
