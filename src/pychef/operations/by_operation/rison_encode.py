"""Dedicated entry point for the Rison Encode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats_extra import rison_encode as _implementation

NAME = "Rison Encode"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
