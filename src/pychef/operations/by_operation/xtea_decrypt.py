"""Dedicated entry point for the XTEA Decrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..modern_ciphers import xtea_decrypt as _implementation

NAME = "XTEA Decrypt"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
