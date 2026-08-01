"""Dedicated entry point for the SM4 Encrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..sm4 import sm4_encrypt as _implementation

NAME = "SM4 Encrypt"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
