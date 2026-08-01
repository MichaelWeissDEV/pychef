"""Dedicated entry point for the ECDSA Sign operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..public_key import ecdsa_sign as _implementation

NAME = "ECDSA Sign"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
