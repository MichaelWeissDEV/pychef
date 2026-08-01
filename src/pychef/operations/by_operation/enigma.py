"""Dedicated entry point for the Enigma operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..rotor_machines import enigma as _implementation

NAME = "Enigma"
CATEGORY = "Bletchley"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
