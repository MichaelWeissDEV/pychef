"""Dedicated entry point for the Protobuf Decode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..remaining_formats import protobuf_decode as _implementation

NAME = "Protobuf Decode"
CATEGORY = "Serialise"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
