"""Dedicated entry point for the Atbash Cipher operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import atbash as _implementation

NAME = "Atbash Cipher"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
