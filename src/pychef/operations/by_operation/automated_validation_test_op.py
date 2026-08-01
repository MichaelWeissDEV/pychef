"""Dedicated entry point for the Automated Validation Test Op operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..flow_more import automated_validation_test_op as _implementation

NAME = "Automated Validation Test Op"
CATEGORY = "Testing"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
