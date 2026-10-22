"""Read and write CyberChef's own recipe representations.

Mirrors ``Utils.parseRecipeConfig``, ``Utils.generatePrettyRecipe``,
``Utils.parseURIParams`` and ``Utils.encodeURIFragment`` of the pinned CyberChef
release, so recipes copied from the CyberChef web app ("Save recipe" in "Chef
format" or "Clean JSON", or a shared link) can be used directly and vice versa.

The "Chef format" looks like ``From_Hex('Auto')To_Base64('A-Za-z0-9+/=')``: operation
names use ``_`` for spaces, arguments are JSON values whose strings use single
quotes, and ``/disabled`` or ``/breakpoint`` flags may follow the arguments.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote, unquote

DEFAULT_BASE_URL = "https://gchq.github.io/CyberChef/"

# encodeURIComponent leaves these unescaped; encodeURIFragment additionally keeps
# "$ , ; : @ / ?" readable. "+", "&" and "=" stay escaped.
_FRAGMENT_SAFE = "-_.!~*'()$,;:@/?"
_DOUBLE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


class CyberChefFormatError(ValueError):
    """The text is not a valid CyberChef recipe, recipe link, or JSON recipe."""


def parse_recipe(text: str) -> list[dict[str, Any]]:
    """Return recipe steps from JSON, Chef format, or a CyberChef link."""
    stripped = text.strip()
    if not stripped:
        return []
    if _looks_like_link(stripped):
        recipe = _link_params(stripped).get("recipe")
        if not isinstance(recipe, str):
            raise CyberChefFormatError("the CyberChef link has no recipe parameter")
        return parse_recipe(recipe)
    if stripped[0] == "[":
        try:
            config = json.loads(stripped)
        except ValueError as exc:
            raise CyberChefFormatError(f"invalid JSON recipe: {exc}") from exc
        if not isinstance(config, list):
            raise CyberChefFormatError("a JSON recipe must be a list of steps")
        return config
    return _parse_pretty(stripped.replace("\r", "").replace("\n", ""))


def _parse_pretty(recipe: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    index = 0
    while index < len(recipe):
        open_paren = recipe.find("(", index)
        if open_paren <= index:
            raise CyberChefFormatError(f"expected an operation name at position {index}")
        name = recipe[index:open_paren].replace("_", " ")
        index = open_paren + 1
        converted: list[str] = []
        flags = ""
        while True:
            if index >= len(recipe):
                raise CyberChefFormatError(f"unterminated arguments for {name!r}")
            char = recipe[index]
            if char == "'":
                index = _read_single_quoted(recipe, index + 1, converted)
                continue
            if char == ")":
                index += 1
                break
            if char == "/":
                close = recipe.find(")", index)
                if close == -1:
                    raise CyberChefFormatError(f"unterminated flags for {name!r}")
                flags = recipe[index:close]
                index = close + 1
                break
            converted.append('\\"' if char == '"' else char)
            index += 1
        try:
            args = json.loads("[" + "".join(converted) + "]")
        except ValueError as exc:
            raise CyberChefFormatError(f"invalid arguments for {name!r}: {exc}") from exc
        step: dict[str, Any] = {"op": name, "args": args}
        if "disabled" in flags:
            step["disabled"] = True
        if "breakpoint" in flags:
            step["breakpoint"] = True
        steps.append(step)
    return steps


def _read_single_quoted(recipe: str, index: int, out: list[str]) -> int:
    """Translate one single-quoted string into a JSON string; return the next index."""
    out.append('"')
    while index < len(recipe):
        char = recipe[index]
        if char == "\\":
            if index + 1 >= len(recipe):
                break
            following = recipe[index + 1]
            # \' is an escaped quote; every other escape is already a JSON escape.
            out.append("'" if following == "'" else "\\" + following)
            index += 2
            continue
        if char == "'":
            out.append('"')
            return index + 1
        out.append('\\"' if char == '"' else char)
        index += 1
    raise CyberChefFormatError("unterminated string in recipe arguments")


def generate_pretty(steps: Sequence[Mapping[str, Any]], *, newline: bool = False) -> str:
    """Render steps in Chef format exactly like CyberChef's ``generatePrettyRecipe``."""
    parts: list[str] = []
    for step in steps:
        name = str(step["op"]).replace(" ", "_")
        try:
            encoded = json.dumps(
                list(step.get("args", ())), ensure_ascii=False, separators=(",", ":")
            )
        except TypeError as exc:
            raise TypeError(f"arguments of {step['op']!r} are not JSON serializable") from exc
        args = encoded[1:-1].replace("'", "\\'")
        args = _DOUBLE_QUOTED.sub(lambda match: "'" + match.group(1) + "'", args)
        args = args.replace('\\"', '"')
        flags = ("/disabled" if step.get("disabled") else "") + (
            "/breakpoint" if step.get("breakpoint") else ""
        )
        parts.append(f"{name}({args}{flags})" + ("\n" if newline else ""))
    return "".join(parts)


def build_link(
    steps: Sequence[Mapping[str, Any]],
    data: bytes | None = None,
    *,
    base_url: str = DEFAULT_BASE_URL,
) -> str:
    """Build a CyberChef link with the recipe and (optionally) the input bytes."""
    params: list[tuple[str, str]] = []
    if steps:
        params.append(("recipe", generate_pretty(steps)))
    if data:
        # CyberChef stores the input as unpadded standard Base64.
        params.append(("input", base64.b64encode(data).decode("ascii").rstrip("=")))
    fragment = "&".join(f"{key}={quote(value, safe=_FRAGMENT_SAFE)}" for key, value in params)
    return f"{base_url}#{fragment}" if fragment else base_url


def link_input(text: str) -> bytes | None:
    """Return the input bytes stored in a CyberChef link, if any."""
    value = _link_params(text.strip()).get("input")
    if not isinstance(value, str) or not value:
        return None
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CyberChefFormatError("the input parameter of the link is not valid Base64") from exc


def _looks_like_link(text: str) -> bool:
    return text.startswith(("http://", "https://", "#", "?", "recipe=", "input="))


def _link_params(text: str) -> dict[str, str | bool]:
    """Parse URL parameters like CyberChef's ``Utils.parseURIParams``."""
    if "#" in text:
        query = text.split("#", 1)[1]
    elif "?" in text:
        query = text.split("?", 1)[1]
    else:
        query = text
    result: dict[str, str | bool] = {}
    for item in query.split("&"):
        if not item:
            continue
        pieces = item.split("=")
        if len(pieces) != 2:
            result[item] = True
        else:
            result[pieces[0]] = unquote(pieces[1].replace("+", " "))
    return result
