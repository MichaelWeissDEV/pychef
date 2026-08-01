"""Dedicated entry point for the Parse X.509 certificate operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..public_key import parse_x509_certificate as _implementation

NAME = "Parse X.509 certificate"
CATEGORY = "Public Key"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
