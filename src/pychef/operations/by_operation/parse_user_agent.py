"""Dedicated entry point for the Parse User Agent operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..analysis_extra import parse_user_agent as _implementation

NAME = "Parse User Agent"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
