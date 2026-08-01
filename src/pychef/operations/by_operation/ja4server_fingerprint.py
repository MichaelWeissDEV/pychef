"""Dedicated entry point for the JA4Server Fingerprint operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..fingerprints import ja4_server as _implementation

NAME = "JA4Server Fingerprint"
CATEGORY = "Crypto"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
