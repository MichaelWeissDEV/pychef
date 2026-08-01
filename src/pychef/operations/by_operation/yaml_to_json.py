"""Dedicated entry point for the YAML to JSON operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats_extra import yaml_to_json as _implementation

NAME = "YAML to JSON"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
