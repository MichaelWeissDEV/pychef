"""Dedicated entry point for the Vigenère Decode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ciphers import vigenere_decode as _implementation

NAME = "Vigenère Decode"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
