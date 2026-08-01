"""Dedicated entry point for the Hex to Object Identifier operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import hex_to_oid as _implementation

NAME = "Hex to Object Identifier"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
