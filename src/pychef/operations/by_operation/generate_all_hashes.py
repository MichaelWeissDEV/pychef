"""Dedicated entry point for the Generate all hashes operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..legacy_crypto import generate_all_hashes as _implementation

NAME = "Generate all hashes"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
