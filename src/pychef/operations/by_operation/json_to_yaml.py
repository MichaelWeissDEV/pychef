"""Dedicated entry point for the JSON to YAML operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..formats_extra import json_to_yaml as _implementation

NAME = "JSON to YAML"
CATEGORY = "Serialisation"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
