"""Dedicated entry point for the Generate PGP Key Pair operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..pgp import generate_pgp_key_pair as _implementation

NAME = "Generate PGP Key Pair"
CATEGORY = "PGP"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
