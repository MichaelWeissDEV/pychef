"""Dedicated entry point for the Object Identifier to Hex operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import oid_to_hex as _implementation

NAME = "Object Identifier to Hex"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
