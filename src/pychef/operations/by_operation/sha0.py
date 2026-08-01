"""Dedicated entry point for the SHA0 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..crypto_extra import sha0 as _implementation

NAME = "SHA0"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
