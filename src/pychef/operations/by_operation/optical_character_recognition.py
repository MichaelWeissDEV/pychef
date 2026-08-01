"""Dedicated entry point for the Optical Character Recognition operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ocr import optical_character_recognition as _implementation

NAME = "Optical Character Recognition"
CATEGORY = "OCR"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
