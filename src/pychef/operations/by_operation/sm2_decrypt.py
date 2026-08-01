"""Dedicated entry point for the SM2 Decrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..sm2 import sm2_decrypt as _implementation

NAME = "SM2 Decrypt"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
