"""Dedicated entry point for the Decode NetBIOS Name operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import decode_netbios as _implementation

NAME = "Decode NetBIOS Name"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
