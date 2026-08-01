"""Dedicated entry point for the Parse UNIX file permissions operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import parse_unix_permissions as _implementation

NAME = "Parse UNIX file permissions"
CATEGORY = "Operating system"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
