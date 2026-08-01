"""Dedicated entry point for the ELF Info operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..elf_info import elf_info as _implementation

NAME = "ELF Info"
CATEGORY = "Analysis"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
