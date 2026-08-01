"""Dedicated entry point for the Disassemble x86 operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..disassembly import disassemble_x86 as _implementation

NAME = "Disassemble x86"
CATEGORY = "Shellcode"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
