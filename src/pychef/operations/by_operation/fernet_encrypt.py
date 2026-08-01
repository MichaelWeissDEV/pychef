"""Dedicated entry point for the Fernet Encrypt operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..fernet import fernet_encrypt as _implementation

NAME = "Fernet Encrypt"
CATEGORY = "Encryption"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
