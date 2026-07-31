"""Dependency-free PHP, Rison, and conservative YAML serialisation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg


@dataclass(slots=True)
class _PHPReader:
    text: str
    position: int = 0

    def read(self, count: int) -> str:
        if count < 0 or self.position + count > len(self.text):
            raise ValueError("end of input reached before end of PHP value")
        result = self.text[self.position : self.position + count]
        self.position += count
        return result

    def expect(self, expected: str) -> None:
        if self.read(len(expected)) != expected:
            raise ValueError(f"expected {expected!r} in PHP value")

    def until(self, delimiter: str) -> str:
        end = self.text.find(delimiter, self.position)
        if end < 0:
            raise ValueError(f"missing delimiter {delimiter!r} in PHP value")
        result = self.text[self.position : end]
        self.position = end + len(delimiter)
        return result


def _php_value(reader: _PHPReader, depth: int = 0) -> Any:
    if depth > 100:
        raise ValueError("PHP value nesting is too deep")
    kind = reader.read(1).lower()
    if kind == "n":
        reader.expect(";")
        return None
    reader.expect(":")
    if kind == "i":
        return int(reader.until(";"))
    if kind == "d":
        return float(reader.until(";"))
    if kind == "b":
        return bool(int(reader.until(";")))
    if kind == "s":
        length = int(reader.until(":"))
        reader.expect('"')
        result = reader.read(length)
        reader.expect('";')
        return result
    if kind == "a":
        count = int(reader.until(":"))
        if count > 1_000_000:
            raise ValueError("PHP array is too large")
        reader.expect("{")
        result: dict[Any, Any] = {}
        for _ in range(count):
            key = _php_value(reader, depth + 1)
            result[key] = _php_value(reader, depth + 1)
        reader.expect("}")
        return result
    raise ValueError(f"unknown PHP serialization type: {kind}")


def _render_php_json(value: Any, valid_json: bool) -> str:
    if isinstance(value, dict):
        entries = []
        for key, item in value.items():
            rendered_key = (
                json.dumps(str(key), ensure_ascii=False)
                if valid_json or isinstance(key, str)
                else str(key)
            )
            entries.append(f"{rendered_key}: {_render_php_json(item, valid_json)}")
        return "{" + ",".join(entries) + "}"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


@operation("PHP Deserialize", category="Serialisation")
def php_deserialize(value: Data, args: Args) -> str:
    reader = _PHPReader(to_text(value))
    parsed = _php_value(reader)
    if reader.position != len(reader.text):
        raise ValueError("trailing data after PHP value")
    return _render_php_json(parsed, bool(arg(args, 0, True)))


_RISON_SAFE = re.compile(r"^[A-Za-z_./~-][A-Za-z0-9_./~-]*$")


def _rison_encode(value: Any) -> str:
    if value is None:
        return "!n"
    if value is True:
        return "!t"
    if value is False:
        return "!f"
    if isinstance(value, (int, float)):
        return json.dumps(value, allow_nan=False, separators=(",", ":"))
    if isinstance(value, str):
        if _RISON_SAFE.fullmatch(value) and not value.startswith(("!", "-")):
            return value
        return "'" + value.replace("!", "!!").replace("'", "!'") + "'"
    if isinstance(value, list):
        return "!(" + ",".join(_rison_encode(item) for item in value) + ")"
    if isinstance(value, dict):
        return (
            "("
            + ",".join(
                f"{_rison_encode(str(key))}:{_rison_encode(value[key])}" for key in sorted(value)
            )
            + ")"
        )
    raise ValueError(f"unsupported Rison value: {type(value).__name__}")


@operation("Rison Encode", category="Serialisation")
def rison_encode(value: Data, args: Args) -> str:
    parsed = json.loads(to_text(value))
    option = str(arg(args, 0, "Encode"))
    encoded = _rison_encode(parsed)
    if option == "Encode Object":
        if not isinstance(parsed, dict):
            raise ValueError("rison.encode_object expects an object argument")
        return encoded[1:-1]
    if option == "Encode Array":
        if not isinstance(parsed, list):
            raise ValueError("rison.encode_array expects an array argument")
        return encoded[2:-1]
    if option == "Encode URI":
        return quote(encoded, safe="!()'*,_-.:~")
    if option != "Encode":
        raise ValueError("invalid Rison encode option")
    return encoded


@dataclass(slots=True)
class _RisonReader:
    text: str
    position: int = 0

    def peek(self) -> str:
        return self.text[self.position : self.position + 1]

    def take(self) -> str:
        if self.position >= len(self.text):
            raise ValueError("unexpected end of Rison value")
        result = self.text[self.position]
        self.position += 1
        return result


def _rison_parse(reader: _RisonReader, depth: int = 0) -> Any:
    if depth > 100:
        raise ValueError("Rison nesting is too deep")
    if reader.peek() == "(":
        reader.take()
        result: dict[str, Any] = {}
        if reader.peek() == ")":
            reader.take()
            return result
        while True:
            key = _rison_parse(reader, depth + 1)
            if not isinstance(key, str) or reader.take() != ":":
                raise ValueError("invalid Rison object key")
            result[key] = _rison_parse(reader, depth + 1)
            delimiter = reader.take()
            if delimiter == ")":
                return result
            if delimiter != ",":
                raise ValueError("invalid Rison object delimiter")
    if reader.peek() == "!":
        reader.take()
        marker = reader.take()
        if marker in {"t", "f", "n"}:
            return {"t": True, "f": False, "n": None}[marker]
        if marker != "(":
            raise ValueError("invalid Rison bang expression")
        result_list: list[Any] = []
        if reader.peek() == ")":
            reader.take()
            return result_list
        while True:
            result_list.append(_rison_parse(reader, depth + 1))
            delimiter = reader.take()
            if delimiter == ")":
                return result_list
            if delimiter != ",":
                raise ValueError("invalid Rison array delimiter")
    if reader.peek() == "'":
        reader.take()
        output = ""
        while True:
            character = reader.take()
            if character == "'":
                return output
            if character == "!":
                escaped = reader.take()
                if escaped not in {"!", "'"}:
                    raise ValueError("invalid Rison string escape")
                character = escaped
            output += character
    start = reader.position
    while reader.peek() and reader.peek() not in ",:()":
        reader.position += 1
    token = reader.text[start : reader.position]
    if not token:
        raise ValueError("empty Rison token")
    if re.fullmatch(r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", token):
        return float(token) if any(character in token for character in ".eE") else int(token)
    return token


@operation("Rison Decode", category="Serialisation")
def rison_decode(value: Data, args: Args) -> str:
    text = to_text(value)
    option = str(arg(args, 0, "Decode"))
    if option == "Decode Object":
        text = f"({text})"
    elif option == "Decode Array":
        text = f"!({text})"
    elif option != "Decode":
        raise ValueError("invalid Rison decode option")
    reader = _RisonReader(text)
    parsed = _rison_parse(reader)
    if reader.position != len(text):
        raise ValueError("trailing data after Rison value")
    return json.dumps(parsed, ensure_ascii=False, indent=4)


def _yaml_scalar(value: str) -> Any:
    stripped = value.strip()
    if stripped in {"null", "Null", "NULL", "~"}:
        return None
    if stripped.lower() in {"true", "false"}:
        return stripped.lower() == "true"
    if re.fullmatch(r"[-+]?\d+", stripped):
        return int(stripped)
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?", stripped):
        return float(stripped)
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        return json.loads(stripped) if stripped[0] == '"' else stripped[1:-1].replace("''", "'")
    return stripped


def _yaml_load(text: str) -> Any:
    lines = text.splitlines()
    result: dict[str, Any] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace() or ":" not in line:
            raise ValueError("only top-level YAML mappings are supported")
        key, raw = line.split(":", 1)
        key = key.strip()
        if raw.strip() in {"|", ">"}:
            folded = raw.strip() == ">"
            block: list[str] = []
            while index < len(lines) and (not lines[index] or lines[index][0].isspace()):
                block.append(
                    lines[index][2:] if lines[index].startswith("  ") else lines[index].lstrip()
                )
                index += 1
            separator = " " if folded else "\n"
            result[key] = separator.join(block) + "\n"
        elif raw.strip().startswith("[") or raw.strip().startswith("{"):
            result[key] = json.loads(raw.strip())
        else:
            result[key] = _yaml_scalar(raw)
    return result


@operation("YAML to JSON", category="Serialisation")
def yaml_to_json(value: Data, _args: Args) -> str:
    return json.dumps(_yaml_load(to_text(value)), ensure_ascii=False, indent=4)


def _yaml_dump_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value).lower()
    if isinstance(value, str) and value and not re.search(r"[:#\[\]{}&,*!|>'\"%@`\n]", value):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


@operation("JSON to YAML", category="Serialisation")
def json_to_yaml(value: Data, _args: Args) -> str:
    parsed = json.loads(to_text(value))
    if not isinstance(parsed, dict):
        raise ValueError("top-level JSON value must be an object for dependency-free YAML output")
    return "".join(f"{key}: {_yaml_dump_scalar(item)}\n" for key, item in parsed.items())
