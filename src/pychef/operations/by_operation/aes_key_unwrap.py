"""Dedicated entry point for the AES Key Unwrap operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..aes import aes_key_unwrap as _implementation

NAME = "AES Key Unwrap"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
