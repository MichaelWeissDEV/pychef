"""Dedicated entry point for the Rabbit operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..rabbit import rabbit as _implementation

NAME = "Rabbit"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
