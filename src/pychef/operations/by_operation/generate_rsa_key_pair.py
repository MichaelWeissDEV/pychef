"""Dedicated entry point for the Generate RSA Key Pair operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..public_key import generate_rsa_key_pair as _implementation

NAME = "Generate RSA Key Pair"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
