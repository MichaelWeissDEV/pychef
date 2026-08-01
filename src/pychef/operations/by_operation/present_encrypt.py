"""Dedicated entry point for the PRESENT Encrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..modern_ciphers import present_encrypt as _implementation

NAME = "PRESENT Encrypt"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
