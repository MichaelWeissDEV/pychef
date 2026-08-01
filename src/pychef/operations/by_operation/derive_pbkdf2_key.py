"""Dedicated entry point for the Derive PBKDF2 key operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..crypto_extra import derive_pbkdf2 as _implementation

NAME = "Derive PBKDF2 key"
CATEGORY = "KDF"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
