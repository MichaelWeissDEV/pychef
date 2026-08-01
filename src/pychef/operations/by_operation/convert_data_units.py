"""Dedicated entry point for the Convert data units operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..utility_extra import convert_data_units as _implementation

NAME = "Convert data units"
CATEGORY = "Data format"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
