"""Dedicated entry point for the Parse SSH Host Key operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import parse_ssh_host_key as _implementation

NAME = "Parse SSH Host Key"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
