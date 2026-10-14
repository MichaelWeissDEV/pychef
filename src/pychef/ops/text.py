"""Text transformations: URL and HTML encoding, ROT13, reversal."""

from __future__ import annotations

from typing import Literal, overload

from ._engine import BytesLike, as_bytes, as_text, coerce_input, run_operation

HtmlEntityFormat = Literal["Named entities", "Numeric entities", "Hex entities"]


def url_encode(value: str | BytesLike, *, encode_all: bool = False) -> str:
    """Percent-encode problematic characters (``URL Encode``)."""
    return as_text(run_operation("URL Encode", value, (encode_all,)))


def url_decode(value: str | BytesLike, *, plus_as_space: bool = True) -> str:
    """Decode percent-encoding (``URL Decode``); ``+`` becomes a space by default."""
    return as_text(run_operation("URL Decode", value, (plus_as_space,)))


def html_encode(
    value: str | BytesLike,
    *,
    convert_all: bool = False,
    format: HtmlEntityFormat = "Named entities",
) -> str:
    """Convert characters to HTML entities (``To HTML Entity``)."""
    return as_text(run_operation("To HTML Entity", value, (convert_all, format)))


def html_decode(value: str | BytesLike) -> str:
    """Convert HTML entities back to characters (``From HTML Entity``)."""
    return as_text(run_operation("From HTML Entity", value))


@overload
def rot13(
    value: str,
    *,
    amount: int = 13,
    lowercase: bool = True,
    uppercase: bool = True,
    numbers: bool = False,
) -> str: ...
@overload
def rot13(
    value: bytes | bytearray | memoryview,
    *,
    amount: int = 13,
    lowercase: bool = True,
    uppercase: bool = True,
    numbers: bool = False,
) -> bytes: ...
def rot13(
    value: str | BytesLike,
    *,
    amount: int = 13,
    lowercase: bool = True,
    uppercase: bool = True,
    numbers: bool = False,
) -> str | bytes:
    """Rotate letters (and optionally digits) by *amount* (``ROT13``).

    Returns ``str`` for ``str`` input and ``bytes`` for bytes-like input.
    """
    data = coerce_input(value)
    result = run_operation("ROT13", data, (lowercase, uppercase, numbers, amount))
    return as_text(result) if isinstance(data, str) else as_bytes(result)


@overload
def reverse(value: str, *, by: Literal["Character", "Line"] = "Character") -> str: ...
@overload
def reverse(
    value: bytes | bytearray | memoryview,
    *,
    by: Literal["Byte", "Character", "Line"] = "Byte",
) -> bytes: ...
def reverse(value: str | BytesLike, *, by: str | None = None) -> str | bytes:
    """Reverse bytes, characters, or lines (``Reverse``).

    ``str`` input is reversed by ``"Character"`` (default) or ``"Line"`` and
    returns ``str``. Bytes-like input defaults to ``"Byte"`` and returns
    ``bytes``. Reversing text byte by byte is rejected because it would
    corrupt multi-byte characters.
    """
    data = coerce_input(value)
    if isinstance(data, str):
        mode = by or "Character"
        if mode == "Byte":
            raise ValueError("reversing text by 'Byte' is not allowed; use bytes input")
    else:
        mode = by or "Byte"
    result = run_operation("Reverse", data, (mode,))
    return as_text(result) if isinstance(data, str) else as_bytes(result)
