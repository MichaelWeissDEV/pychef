"""Dedicated entry point for the ROT13 Brute Force operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..utility_extra import rot13_brute_force as _implementation

NAME = "ROT13 Brute Force"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
