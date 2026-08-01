"""Dedicated entry point for the LM Hash operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..des import lm_hash as _implementation

NAME = "LM Hash"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
