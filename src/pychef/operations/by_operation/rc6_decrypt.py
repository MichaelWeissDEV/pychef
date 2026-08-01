"""Dedicated entry point for the RC6 Decrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..rc6 import rc6_decrypt as _implementation

NAME = "RC6 Decrypt"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
