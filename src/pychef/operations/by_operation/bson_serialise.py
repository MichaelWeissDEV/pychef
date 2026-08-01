"""Dedicated entry point for the BSON serialise operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..binary_formats import bson_serialize as _implementation

NAME = "BSON serialise"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
