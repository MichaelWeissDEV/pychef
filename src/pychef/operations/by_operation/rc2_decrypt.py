"""Dedicated entry point for the RC2 Decrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..rc2 import rc2_decrypt as _implementation

NAME = "RC2 Decrypt"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
