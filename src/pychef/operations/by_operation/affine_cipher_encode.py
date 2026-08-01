"""Dedicated entry point for the Affine Cipher Encode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import affine_encode as _implementation

NAME = "Affine Cipher Encode"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
