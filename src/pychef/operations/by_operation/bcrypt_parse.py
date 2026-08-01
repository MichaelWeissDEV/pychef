"""Dedicated entry point for the Bcrypt parse operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..bcrypt_parse import bcrypt_parse as _implementation

NAME = "Bcrypt parse"
CATEGORY = "Hashing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
