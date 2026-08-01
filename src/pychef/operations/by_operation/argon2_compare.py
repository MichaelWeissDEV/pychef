"""Dedicated entry point for the Argon2 compare operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..password_hashes import argon2_compare as _implementation

NAME = "Argon2 compare"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
