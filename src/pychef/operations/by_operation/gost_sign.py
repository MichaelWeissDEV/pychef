"""Dedicated entry point for the GOST Sign operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..legacy_crypto import gost_sign as _implementation

NAME = "GOST Sign"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
