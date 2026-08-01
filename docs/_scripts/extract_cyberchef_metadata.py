"""Extract documentation metadata from a pinned CyberChef source checkout.

The extractor is intentionally Python-only and treats upstream ``.mjs`` files
as text. It never executes JavaScript or requires Node.js. The generated JSON
is committed so normal Sphinx and Read the Docs builds do not need an upstream
checkout.
"""

from __future__ import annotations

import argparse
import ast
import html
import json
import re
from pathlib import Path
from typing import Any

PINNED_COMMIT = "c56dd23358e948aff9f3f98913818e544227da13"
PINNED_VERSION = "11.3.0"


def expression_after(source: str, pattern: str) -> str | None:
    """Return one JavaScript expression following *pattern*."""
    match = re.search(pattern, source, re.MULTILINE)
    if match is None:
        return None
    return scan_expression(source, match.end())


def scan_expression(source: str, start: int, *, stop: str = ";,") -> str:
    """Read until a top-level delimiter while respecting strings and nesting."""
    position = start
    while position < len(source) and source[position].isspace():
        position += 1
    begin = position
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    while position < len(source):
        character = source[position]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            position += 1
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character in pairs:
            stack.append(pairs[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif not stack and character in stop:
            break
        position += 1
    return source[begin:position].strip()


def string_values(expression: str | None) -> list[str]:
    """Decode string literals found in a JavaScript expression."""
    if not expression:
        return []
    values: list[str] = []
    position = 0
    while position < len(expression):
        quote = expression[position]
        if quote not in {'"', "'", "`"}:
            position += 1
            continue
        begin = position
        position += 1
        escaped = False
        while position < len(expression):
            character = expression[position]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                position += 1
                break
            position += 1
        token = expression[begin:position]
        try:
            if quote == '"':
                values.append(json.loads(token))
            elif quote == "'":
                values.append(ast.literal_eval(token))
            else:
                body = token[1:-1]
                values.append(bytes(body, "utf-8").decode("unicode_escape"))
        except (ValueError, SyntaxError, UnicodeDecodeError, json.JSONDecodeError):
            values.append(token[1:-1])
    return values


def first_string(expression: str | None, default: str = "") -> str:
    values = string_values(expression)
    return values[0] if values else default


def clean_description(expression: str | None) -> str:
    """Convert upstream HTML-heavy descriptions into readable plain text."""
    text = "".join(string_values(expression))
    substitutions = (
        (r"<br\s*/?>", "\n"),
        (r"</?(?:p|div|ul|ol|table|tr|h[1-6])[^>]*>", "\n"),
        (r"<li[^>]*>", "\n- "),
        (r"</li>", ""),
        (r"<code[^>]*>", "``"),
        (r"</code>", "``"),
        (r"<[^>]+>", ""),
    )
    for pattern, replacement in substitutions:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    text = html.unescape(text).replace("\r", "")
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def top_level_objects(expression: str | None) -> list[str]:
    """Return object literals directly contained in an array expression."""
    if not expression:
        return []
    objects: list[str] = []
    depth = 0
    begin: int | None = None
    quote: str | None = None
    escaped = False
    for position, character in enumerate(expression):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
            continue
        if character == "{":
            if depth == 0:
                begin = position
            depth += 1
        elif character == "}" and depth:
            depth -= 1
            if depth == 0 and begin is not None:
                objects.append(expression[begin : position + 1])
                begin = None
    return objects


def top_level_items(expression: str) -> list[str]:
    """Split an array or object body without splitting nested expressions."""
    text = expression.strip()
    if len(text) >= 2 and (text[0], text[-1]) in {("[", "]"), ("{", "}")}:
        text = text[1:-1]
    items: list[str] = []
    begin = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for position, character in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character in pairs:
            stack.append(pairs[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif character == "," and not stack:
            item = text[begin:position].strip()
            if item:
                items.append(item)
            begin = position + 1
    item = text[begin:].strip()
    if item:
        items.append(item)
    return items


def property_expression(object_source: str, name: str) -> str | None:
    pattern = rf"(?:^|[,{{])\s*[\"']?{re.escape(name)}[\"']?\s*:"
    match = re.search(pattern, object_source, re.MULTILINE)
    if match is None:
        return None
    return scan_expression(object_source, match.end(), stop=",}")


def scalar_value(expression: str | None) -> Any:
    """Convert simple JavaScript scalar expressions to JSON values."""
    if expression is None:
        return None
    text = expression.strip()
    strings = string_values(text)
    if strings and text[0] in {'"', "'", "`"}:
        return strings[0]
    if text in {"true", "false"}:
        return text == "true"
    if text == "null":
        return None
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


def constant_expression(source: str, name: str) -> str | None:
    return expression_after(source, rf"(?:export\s+)?const\s+{re.escape(name)}\s*=")


def imported_constant(path: Path, source: str, name: str) -> tuple[str, Path] | None:
    """Find a named constant in a relative ES module import."""
    pattern = re.compile(
        r"import\s*\{(?P<names>.*?)\}\s*from\s*[\"'](?P<module>[^\"']+)[\"']",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        for imported in match.group("names").split(","):
            original, separator, alias = imported.strip().partition(" as ")
            local_name = alias.strip() if separator else original.strip()
            if local_name != name:
                continue
            imported_path = (path.parent / match.group("module")).resolve()
            if not imported_path.is_file():
                return None
            imported_source = imported_path.read_text(encoding="utf-8")
            expression = constant_expression(imported_source, original.strip())
            if expression is not None:
                return expression, imported_path
    return None


def resolve_constant(
    expression: str,
    source: str,
    path: Path,
) -> tuple[str, str, Path] | None:
    """Resolve one local or relatively imported constant expression."""
    name = expression.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", name) is None:
        return None
    local = constant_expression(source, name)
    if local is not None:
        return name, local, path
    imported = imported_constant(path, source, name)
    if imported is None:
        return None
    resolved, imported_path = imported
    return name, resolved, imported_path


def object_keys(expression: str) -> list[str]:
    keys: list[str] = []
    for item in top_level_items(expression):
        key_expression, separator, _value = item.partition(":")
        if not separator:
            continue
        key = first_string(key_expression)
        if key:
            keys.append(key)
    return keys


def choice_values(
    expression: str | None,
    source: str,
    path: Path,
    *,
    depth: int = 0,
) -> list[str]:
    """Resolve static option values without evaluating upstream JavaScript."""
    if not expression or depth > 8:
        return []
    text = expression.strip()

    literal = scalar_value(text)
    if text.startswith(('"', "'", "`")) and isinstance(literal, str):
        return [literal]

    split_match = re.fullmatch(r"([\"'`].*[\"'`])\.split\([\"']{2}\)", text, re.DOTALL)
    if split_match:
        value = first_string(split_match.group(1))
        return list(value)

    keys_match = re.fullmatch(r"Object\.keys\((.+)\)", text, re.DOTALL)
    if keys_match:
        target = keys_match.group(1).strip()
        resolved = resolve_constant(target, source, path)
        if resolved is None:
            return []
        _name, target_expression, target_path = resolved
        target_source = target_path.read_text(encoding="utf-8")
        return object_keys(target_expression) or choice_values(
            target_expression,
            target_source,
            target_path,
            depth=depth + 1,
        )

    resolved = resolve_constant(text, source, path)
    if resolved is not None:
        _name, target_expression, target_path = resolved
        return choice_values(
            target_expression,
            target_path.read_text(encoding="utf-8"),
            target_path,
            depth=depth + 1,
        )

    concat_match = re.fullmatch(r"(.+)\.concat\((.+)\)", text, re.DOTALL)
    if concat_match:
        return choice_values(concat_match.group(1), source, path, depth=depth + 1) + choice_values(
            concat_match.group(2), source, path, depth=depth + 1
        )

    if not (text.startswith("[") and text.endswith("]")):
        return []
    choices: list[str] = []
    for item in top_level_items(text):
        if item.startswith("..."):
            choices.extend(choice_values(item[3:], source, path, depth=depth + 1))
            continue
        if item.startswith("{"):
            value = scalar_value(property_expression(item, "value"))
            name = scalar_value(property_expression(item, "name"))
            selected = value if isinstance(value, str) else name
            if isinstance(selected, str):
                choices.append(selected)
            continue
        value = scalar_value(item)
        if isinstance(value, str) and value != item:
            choices.append(value)
            continue
        nested = choice_values(item, source, path, depth=depth + 1)
        if nested:
            choices.extend(nested)
    return choices


def argument_metadata(expression: str | None, source: str, path: Path) -> list[dict[str, Any]]:
    """Extract ordered option metadata from a ``this.args`` expression."""
    arguments: list[dict[str, Any]] = []
    for index, object_source in enumerate(top_level_objects(expression)):
        name = first_string(property_expression(object_source, "name"), f"Argument {index}")
        kind = first_string(property_expression(object_source, "type"), "value")
        value_expression = property_expression(object_source, "value")
        toggle_expression = property_expression(object_source, "toggleValues")
        choices = [
            choice
            for choice in choice_values(value_expression, source, path)
            if re.fullmatch(r"\[/?[^]]+\]", choice) is None
        ]
        if kind == "argSelector":
            choices = []
            for choice_object in top_level_objects(value_expression):
                choice = first_string(property_expression(choice_object, "name"))
                if choice:
                    choices.append(choice)
        toggle_values = string_values(toggle_expression)

        default: Any = scalar_value(value_expression)
        if choices and kind in {"option", "editableOption", "argSelector"}:
            default = choices[0]
        if kind == "toggleString":
            default = {
                "string": scalar_value(value_expression) or "",
                "option": toggle_values[0] if toggle_values else "UTF8",
            }
        arguments.append(
            {
                "index": index,
                "name": name,
                "type": kind,
                "default": default,
                "choices": choices,
                "toggle_values": toggle_values,
                "upstream_expression": re.sub(r"\s+", " ", value_expression or "").strip(),
            }
        )
    return arguments


def operation_metadata(path: Path) -> dict[str, Any] | None:
    source = path.read_text(encoding="utf-8")
    name_expression = expression_after(source, r"this\.name\s*=")
    name = first_string(name_expression)
    if not name:
        return None
    return {
        "name": name,
        "module": first_string(expression_after(source, r"this\.module\s*=")),
        "description": clean_description(expression_after(source, r"this\.description\s*=")),
        "info_url": first_string(expression_after(source, r"this\.infoURL\s*=")),
        "input_type": first_string(expression_after(source, r"this\.inputType\s*="), "Data"),
        "output_type": first_string(
            expression_after(source, r"this\.(?:presentType|outputType)\s*="), "Data"
        ),
        "flow_control": scalar_value(expression_after(source, r"this\.flowControl\s*=")) or False,
        "manual_bake": scalar_value(expression_after(source, r"this\.manualBake\s*=")) or False,
        "arguments": argument_metadata(expression_after(source, r"this\.args\s*="), source, path),
        "upstream_file": path.name,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cyberchef", type=Path, help="CyberChef source checkout")
    parser.add_argument("output", type=Path, help="JSON file to create")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    operations_dir = args.cyberchef / "src" / "core" / "operations"
    if not operations_dir.is_dir():
        raise SystemExit(f"not a CyberChef source checkout: {args.cyberchef}")
    extracted = [
        item
        for path in sorted(operations_dir.glob("*.mjs"))
        if (item := operation_metadata(path)) is not None
    ]
    by_name: dict[str, dict[str, Any]] = {}
    for item in extracted:
        previous = by_name.get(item["name"])
        if previous is not None:
            comparable_previous = {
                key: value for key, value in previous.items() if key != "upstream_file"
            }
            comparable_item = {key: value for key, value in item.items() if key != "upstream_file"}
            if comparable_previous != comparable_item:
                raise RuntimeError(f"conflicting upstream metadata for {item['name']!r}")
            continue
        by_name[item["name"]] = item
    metadata = list(by_name.values())
    metadata.sort(key=lambda item: item["name"].casefold())
    document = {
        "source": "https://github.com/gchq/CyberChef",
        "version": PINNED_VERSION,
        "commit": PINNED_COMMIT,
        "operations": metadata,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Wrote {len(metadata)} operation records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
