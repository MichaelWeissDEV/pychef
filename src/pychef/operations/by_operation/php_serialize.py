"""Dedicated entry point for the PHP Serialize operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats import php_serialize as _implementation

NAME = "PHP Serialize"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
