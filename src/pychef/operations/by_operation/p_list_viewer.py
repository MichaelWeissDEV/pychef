"""Dedicated entry point for the P-list Viewer operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats import plist_viewer as _implementation

NAME = "P-list Viewer"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
