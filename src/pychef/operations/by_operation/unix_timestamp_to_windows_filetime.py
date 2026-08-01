"""Dedicated entry point for the UNIX Timestamp to Windows Filetime operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..datetime_ops import unix_to_windows_filetime as _implementation

NAME = "UNIX Timestamp to Windows Filetime"
CATEGORY = "Date / Time"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
