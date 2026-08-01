"""Dedicated entry point for the Ascon Encrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ascon import ascon_encrypt as _implementation

NAME = "Ascon Encrypt"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
