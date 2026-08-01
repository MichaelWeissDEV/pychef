"""Dedicated entry point for the RC4 Drop operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..modern_ciphers import rc4_drop as _implementation

NAME = "RC4 Drop"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
