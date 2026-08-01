"""Dedicated entry point for the Microsoft Script Decoder operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..microsoft_script import microsoft_script_decoder as _implementation

NAME = "Microsoft Script Decoder"
CATEGORY = "Default"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
