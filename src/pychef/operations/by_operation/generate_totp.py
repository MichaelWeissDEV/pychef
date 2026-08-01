"""Dedicated entry point for the Generate TOTP operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..crypto_extra import generate_totp as _implementation

NAME = "Generate TOTP"
CATEGORY = "KDF"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
