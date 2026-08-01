"""Dedicated entry point for the CMAC operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..cmac import cmac as _implementation

NAME = "CMAC"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
