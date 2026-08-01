"""Dedicated entry point for the PGP Decrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..pgp import pgp_decrypt as _implementation

NAME = "PGP Decrypt"
CATEGORY = "PGP"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
