"""Dedicated entry point for the AES Key Wrap operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..aes import aes_key_wrap as _implementation

NAME = "AES Key Wrap"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
