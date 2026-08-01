"""Dedicated entry point for the XML Beautify operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats import xml_beautify as _implementation

NAME = "XML Beautify"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
