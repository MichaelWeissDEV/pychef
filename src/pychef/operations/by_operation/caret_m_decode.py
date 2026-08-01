"""Dedicated entry point for the Caret/M-decode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..misc import caret_m_decode as _implementation

NAME = "Caret/M-decode"
CATEGORY = "Encoding"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
