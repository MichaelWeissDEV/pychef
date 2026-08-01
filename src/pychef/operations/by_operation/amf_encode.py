"""Dedicated entry point for the AMF Encode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..remaining_formats import amf_encode as _implementation

NAME = "AMF Encode"
CATEGORY = "Encodings"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
