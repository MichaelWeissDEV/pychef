"""Dedicated entry point for the Tar operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..compression import tar_archive as _implementation

NAME = "Tar"
CATEGORY = "Compression"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
