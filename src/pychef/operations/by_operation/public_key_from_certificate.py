"""Dedicated entry point for the Public Key from Certificate operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..public_key import public_key_from_certificate as _implementation

NAME = "Public Key from Certificate"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
