"""Dedicated entry point for the PHP Deserialize operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats_extra import php_deserialize as _implementation

NAME = "PHP Deserialize"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
