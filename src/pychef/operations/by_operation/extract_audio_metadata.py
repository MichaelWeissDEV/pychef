"""Dedicated entry point for the Extract Audio Metadata operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..remaining_formats import extract_audio_metadata as _implementation

NAME = "Extract Audio Metadata"
CATEGORY = "Forensics"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
