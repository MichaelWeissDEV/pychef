"""Bitwise helpers."""

from __future__ import annotations

from typing import Literal

from ..ctf import decode_bytes
from ._engine import BytesLike, as_bytes, coerce_input, run_operation

XorKeyFormat = Literal["raw", "hex", "base64", "latin1"]
XorScheme = Literal["Standard", "Input differential", "Output differential", "Cascade"]

_KEY_OPTIONS = frozenset({"raw", "hex", "base64", "latin1"})


def xor(
    value: str | BytesLike,
    key: str | BytesLike,
    *,
    key_format: XorKeyFormat = "raw",
    scheme: XorScheme = "Standard",
    null_preserving: bool = False,
) -> bytes:
    """XOR *value* with a repeating *key* (``XOR``) and return bytes.

    ``str`` input and ``str`` keys in ``"raw"`` format are UTF-8 encoded. Use
    ``key_format`` to pass a ``hex``, ``base64`` or ``latin1`` encoded text key.
    ``bytes`` keys are decoded with ``key_format`` exactly like ``Pipeline.xor`` (so
    ``b"4142"`` with ``key_format="hex"`` is the two-byte key ``b"AB"``). An empty key is rejected.
    """
    if key_format not in _KEY_OPTIONS:
        raise ValueError(f"key_format must be one of {sorted(_KEY_OPTIONS)}, got {key_format!r}")
    key_data = coerce_input(key)
    decoded = decode_bytes(key_data, format=key_format)
    if not decoded:
        raise ValueError("XOR key must not be empty")
    key_arg = {"string": decoded.decode("latin-1"), "option": "Latin1"}
    return as_bytes(run_operation("XOR", value, (key_arg, scheme, null_preserving)))
