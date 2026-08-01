"""Dedicated entry point for the PEM to JWK operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..public_key import pem_to_jwk as _implementation

NAME = "PEM to JWK"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
