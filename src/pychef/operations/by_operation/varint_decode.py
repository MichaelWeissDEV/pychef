"""Dedicated entry point for the VarInt Decode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats import varint_decode as _implementation

NAME = "VarInt Decode"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
