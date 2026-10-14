"""Hex, Base64, and Base32 helpers."""

from __future__ import annotations

from typing import Literal

from ._engine import BytesLike, as_bytes, as_text, run_operation

HexDelimiter = Literal[
    "Auto",
    "Space",
    "Percent",
    "Comma",
    "Semi-colon",
    "Colon",
    "Line feed",
    "CRLF",
    "0x",
    "0x with comma",
    "\\x",
    "None",
]
HexOutputDelimiter = Literal[
    "Space",
    "Percent",
    "Comma",
    "Semi-colon",
    "Colon",
    "Line feed",
    "CRLF",
    "0x",
    "0x with comma",
    "\\x",
    "None",
]


def from_hex(value: str | BytesLike, *, delimiter: HexDelimiter = "Auto") -> bytes:
    """Decode hexadecimal text to bytes (CyberChef ``From Hex``).

    *delimiter* names the separator between bytes; ``"Auto"`` detects it.
    """
    return as_bytes(run_operation("From Hex", value, (delimiter,)))


def to_hex(
    value: str | BytesLike,
    *,
    delimiter: HexOutputDelimiter = "None",
    bytes_per_line: int = 0,
) -> str:
    """Encode bytes (or UTF-8 encoded text) as hexadecimal text (``To Hex``).

    The default delimiter is ``"None"`` (``"414243"``), matching
    :meth:`Pipeline.to_hex`. A recipe step without arguments uses ``"Space"``.
    """
    return as_text(run_operation("To Hex", value, (delimiter, bytes_per_line)))


def from_base64(
    value: str | BytesLike,
    *,
    alphabet: str = "A-Za-z0-9+/=",
    remove_non_alphabet: bool = True,
    strict: bool = False,
) -> bytes:
    """Decode Base64 text to bytes (``From Base64``)."""
    return as_bytes(run_operation("From Base64", value, (alphabet, remove_non_alphabet, strict)))


def to_base64(value: str | BytesLike, *, alphabet: str = "A-Za-z0-9+/=") -> str:
    """Encode bytes (or UTF-8 encoded text) as Base64 text (``To Base64``)."""
    return as_text(run_operation("To Base64", value, (alphabet,)))


def from_base32(
    value: str | BytesLike,
    *,
    alphabet: str = "A-Z2-7=",
    remove_non_alphabet: bool = True,
) -> bytes:
    """Decode Base32 text to bytes (``From Base32``)."""
    return as_bytes(run_operation("From Base32", value, (alphabet, remove_non_alphabet)))


def to_base32(value: str | BytesLike, *, alphabet: str = "A-Z2-7=") -> str:
    """Encode bytes (or UTF-8 encoded text) as Base32 text (``To Base32``)."""
    return as_text(run_operation("To Base32", value, (alphabet,)))
