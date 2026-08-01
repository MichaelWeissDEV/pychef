"""Dedicated entry point for the Show Base64 offsets operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..utility_extra import show_base64_offsets as _implementation

NAME = "Show Base64 offsets"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
