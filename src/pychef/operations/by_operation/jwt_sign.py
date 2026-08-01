"""Dedicated entry point for the JWT Sign operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..web_tokens import jwt_sign as _implementation

NAME = "JWT Sign"
CATEGORY = "Authentication"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
