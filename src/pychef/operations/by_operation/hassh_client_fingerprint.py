"""Dedicated entry point for the HASSH Client Fingerprint operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..fingerprints import hassh_client as _implementation

NAME = "HASSH Client Fingerprint"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
