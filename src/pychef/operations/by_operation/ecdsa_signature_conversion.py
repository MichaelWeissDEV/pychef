"""Dedicated entry point for the ECDSA Signature Conversion operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..ecdsa_conversion import ecdsa_signature_conversion as _implementation

NAME = "ECDSA Signature Conversion"
CATEGORY = "Ciphers"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
