"""Dedicated entry point for the Multiple Bombe operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..rotor_machines import multiple_bombe as _implementation

NAME = "Multiple Bombe"
CATEGORY = "Bletchley"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
