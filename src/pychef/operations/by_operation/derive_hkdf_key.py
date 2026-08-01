"""Dedicated entry point for the Derive HKDF key operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..crypto_extra import derive_hkdf as _implementation

NAME = "Derive HKDF key"
CATEGORY = "KDF"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
