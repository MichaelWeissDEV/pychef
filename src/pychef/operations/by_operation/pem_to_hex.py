"""Dedicated entry point for the PEM to Hex operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import pem_to_hex as _implementation

NAME = "PEM to Hex"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
