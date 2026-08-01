"""Dedicated entry point for the Bifid Cipher Decode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..bifid import bifid_decode as _implementation

NAME = "Bifid Cipher Decode"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
