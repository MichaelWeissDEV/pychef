"""Dedicated entry point for the Parse ASN.1 hex string operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..protocols import parse_asn1_hex as _implementation

NAME = "Parse ASN.1 hex string"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
