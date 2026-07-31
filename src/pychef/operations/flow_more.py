"""Flow-control markers, automatic inspection, and validation support."""

from __future__ import annotations

import base64
import json
import math
import re

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg


def _identity(value: Data, args: Args) -> Data:
    del args
    return value


for _name in ("Conditional Jump", "Fork", "Jump", "Merge", "Register", "Subsection"):
    operation(_name, category="Flow control")(_identity)


@operation("Automated Validation Test Op", category="Testing")
def automated_validation_test_op(value: Data, args: Args) -> Data:
    del value
    integer = arg(args, 0, 5)
    real = arg(args, 1, 1.5)
    nonempty = str(arg(args, 2, "hello"))
    toggle = arg(args, 4, {"option": "Option A", "string": "test"})
    option = str(arg(args, 5, "Option 1"))
    selector = str(arg(args, 6, "Option 1"))
    if isinstance(integer, float) and not integer.is_integer() or not 5 <= int(integer) <= 10:
        raise ValueError("Integer Number must be an integer between 5 and 10")
    if not 1.5 <= float(real) <= 5.5:
        raise ValueError("Real Number must be between 1.5 and 5.5")
    if not nonempty or len(nonempty) > 5:
        raise ValueError("Non Empty String must contain between 1 and 5 characters")
    if not isinstance(toggle, dict) or not str(toggle.get("string", "")):
        raise ValueError("Non Empty Toggle String cannot be empty")
    if option not in {"Option 1", "Option 2", "Option 3"}:
        raise ValueError("Invalid Option Ingredient")
    if selector not in {"Option 1", "Option 2"}:
        raise ValueError("Invalid Arg Selector Ingredient")
    return "Success"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {byte: data.count(byte) for byte in set(data)}
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


@operation("Magic", category="Analysis")
def magic(value: Data, args: Args) -> Data:
    data = to_bytes(value)
    crib = str(arg(args, 3, ""))
    suggestions: list[dict[str, object]] = []

    def add(name: str, decoded: bytes) -> None:
        text = decoded.decode("utf-8", "replace")
        if crib and re.search(crib, text, re.IGNORECASE) is None:
            return
        suggestions.append(
            {
                "recipe": [{"op": name, "args": []}],
                "data": text,
                "entropy": _entropy(decoded),
                "isUTF8": True,
                "matchesCrib": bool(crib),
            }
        )

    text = to_text(value).strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", text):
        try:
            add("From Hex", bytes.fromhex(text))
        except ValueError:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/\s]+={0,2}", text) and len(text.replace(" ", "")) % 4 == 0:
        try:
            add("From Base64", base64.b64decode(text, validate=True))
        except ValueError:
            pass
    if data.startswith(b"\x89PNG"):
        suggestions.append({"recipe": [{"op": "Render Image", "args": []}], "data": "PNG image", "entropy": _entropy(data), "isUTF8": False})
    return json.dumps(suggestions, ensure_ascii=False, indent=2)
