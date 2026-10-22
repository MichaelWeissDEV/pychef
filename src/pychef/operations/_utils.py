"""Internal helpers shared by operation families."""

from __future__ import annotations

from typing import Any, TypeVar, cast


from ..types import Args

T = TypeVar("T")


def arg(args: Args, index: int, default: T) -> T:
    """Read an argument while preserving CyberChef defaults for missing values."""
    if index >= len(args) or args[index] is None:
        return default
    return cast(T, args[index])


def char_rep(name: Any, default: str = " ") -> str:
    """Translate CyberChef's human-readable delimiter names."""
    if name is None or name == "":
        return default
    return {
        "Space": " ",
        "Percent": "%",
        "Comma": ",",
        "Semi-colon": ";",
        "Colon": ":",
        "Line feed": "\n",
        "CRLF": "\r\n",
        "Tab": "\t",
        "Forward slash": "/",
        "Backslash": "\\",
        "Hyphen": "-",
        "None": "",
    }.get(str(name), str(name))


def expand_alphabet(specification: str) -> str:
    """Expand CyberChef alphabet descriptors such as ``A-Za-z0-9``."""
    tokens: list[tuple[str, bool]] = []
    index = 0
    while index < len(specification):
        if specification[index] == "\\" and index + 1 < len(specification):
            tokens.append((specification[index + 1], True))
            index += 2
        else:
            tokens.append((specification[index], False))
            index += 1

    expanded: list[str] = []
    index = 0
    while index < len(tokens):
        if index + 2 < len(tokens) and tokens[index + 1][0] == "-" and not tokens[index + 1][1]:
            start, end = ord(tokens[index][0]), ord(tokens[index + 2][0])
            step = 1 if end >= start else -1
            expanded.extend(chr(codepoint) for codepoint in range(start, end + step, step))
            index += 3
        else:
            expanded.append(tokens[index][0])
            index += 1
    return "".join(expanded)


def require_int(value: Any, *, name: str = "value") -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
