"""Dedicated entry point for the Play Media operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..presentation import play_media as _implementation

NAME = "Play Media"
CATEGORY = "Rendering"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
