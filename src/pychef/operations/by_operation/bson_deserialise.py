"""Dedicated entry point for the BSON deserialise operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..binary_formats import bson_deserialize as _implementation

NAME = "BSON deserialise"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
