"""Dedicated entry point for the RSA Verify operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..public_key import rsa_verify as _implementation

NAME = "RSA Verify"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
