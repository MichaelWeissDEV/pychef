"""Dedicated entry point for the Flask Session Decode operation."""

from __future__ import annotations

from ...registry import operation
from ...types import Args, Data
from ..web_tokens import flask_session_decode as _implementation

NAME = "Flask Session Decode"
CATEGORY = "Authentication"


@operation(NAME, category=CATEGORY)
def run(value: Data, args: Args) -> Data:
    """Run this operation using its shared internal implementation."""
    return _implementation(value, args)


__all__ = ["CATEGORY", "NAME", "run"]
