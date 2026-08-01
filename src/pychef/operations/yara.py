"""A safe, dependency-free implementation of commonly used YARA rule features."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg


@dataclass(frozen=True, slots=True)
class _Match:
    identifier: str
    position: int
    data: bytes


@dataclass(frozen=True, slots=True)
class _Pattern:
    identifier: str
    expression: bytes | re.Pattern[bytes]
    modifiers: frozenset[str]
    line: int


@dataclass(frozen=True, slots=True)
class _Rule:
    name: str
    metadata: tuple[tuple[str, Any], ...]
    patterns: tuple[_Pattern, ...]
    condition: str


def _rules(source: str) -> list[tuple[str, str, int]]:
    output: list[tuple[str, str, int]] = []
    matcher = re.compile(r"\b(?:private\s+|global\s+)?rule\s+([A-Za-z_]\w*)[^\{]*\{")
    position = 0
    while match := matcher.search(source, position):
        depth = 1
        quote = ""
        regex = False
        escaped = False
        cursor = match.end()
        while cursor < len(source) and depth:
            character = source[cursor]
            if escaped:
                escaped = False
            elif quote:
                if character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif regex:
                if character == "\\":
                    escaped = True
                elif character == "/":
                    regex = False
            elif character in "'\"":
                quote = character
            elif character == "/" and cursor + 1 < len(source) and source[cursor + 1] not in "/*":
                regex = True
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
            cursor += 1
        if depth:
            raise ValueError(
                f"Error on line {source.count(chr(10), 0, match.start()) + 1}: unterminated rule"
            )
        output.append(
            (
                match.group(1),
                source[match.end() : cursor - 1],
                source.count("\n", 0, match.start()) + 1,
            )
        )
        position = cursor
    if not output:
        raise ValueError("Error on line 1: no rules found")
    return output


def _section(body: str, name: str, following: tuple[str, ...]) -> str:
    start = re.search(rf"\b{name}\s*:", body, re.IGNORECASE)
    if start is None:
        return ""
    end = len(body)
    for candidate in following:
        found = re.search(rf"\b{candidate}\s*:", body[start.end() :], re.IGNORECASE)
        if found:
            end = min(end, start.end() + found.start())
    return body[start.end() : end]


def _hex_regex(expression: str) -> re.Pattern[bytes]:
    pieces: list[bytes] = []
    tokens = re.findall(
        r"\[[0-9]+(?:-[0-9]+)?\]|\?\?|\?[0-9A-Fa-f]|[0-9A-Fa-f]\?|[0-9A-Fa-f]{2}|\([^)]*\)",
        expression,
    )
    for token in tokens:
        if token == "??":
            pieces.append(b"[\\s\\S]")
        elif token.startswith("["):
            bounds = token[1:-1].split("-")
            maximum = bounds[-1]
            pieces.append(f"[\\s\\S]{{{bounds[0]},{maximum}}}".encode())
        elif token.startswith("("):
            choices = [bytes.fromhex(choice.strip()) for choice in token[1:-1].split("|")]
            pieces.append(b"(?:" + b"|".join(re.escape(choice) for choice in choices) + b")")
        elif "?" in token:
            high, low = token
            high_part = b"." if high == "?" else f"\\x{int(high, 16):x}".encode()
            low_part = b"." if low == "?" else low.encode()
            if high == "?":
                pieces.append(f"[\\x0{low}-\\xf{low}]".encode())
            elif low == "?":
                pieces.append(f"[\\x{high}0-\\x{high}f]".encode())
            else:
                pieces.append(high_part + low_part)
        else:
            pieces.append(re.escape(bytes.fromhex(token)))
    return re.compile(b"".join(pieces), re.DOTALL)


_STRING_DEF = re.compile(
    r"(?m)^\s*(\$[A-Za-z_]\w*)\s*=\s*(\"(?:\\.|[^\"\\])*\"|/[^/\n]*(?:/[is]*)?|\{[^}]*\})\s*([^\r\n}]*)"
)


def _parse_rule(name: str, body: str, base_line: int) -> _Rule:
    meta_source = _section(body, "meta", ("strings", "condition"))
    strings_source = _section(body, "strings", ("condition",))
    condition = _section(body, "condition", ()).strip()
    if not condition:
        raise ValueError(f"Error on line {base_line}: missing condition")
    metadata: list[tuple[str, Any]] = []
    for match in re.finditer(
        r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(\"(?:\\.|[^\"\\])*\"|-?\d+|true|false)", meta_source
    ):
        raw = match.group(2)
        if raw.startswith('"'):
            value: Any = bytes(raw[1:-1], "utf-8").decode("unicode_escape")
        elif raw in {"true", "false"}:
            value = raw == "true"
        else:
            value = int(raw)
        metadata.append((match.group(1), value))
    patterns: list[_Pattern] = []
    for match in _STRING_DEF.finditer(strings_source):
        identifier, raw = match.group(1), match.group(2)
        modifiers = frozenset(match.group(3).lower().split())
        line = base_line + body.count("\n", 0, body.find(match.group(1)))
        if raw.startswith('"'):
            expression: bytes | re.Pattern[bytes] = (
                bytes(raw[1:-1], "utf-8").decode("unicode_escape").encode("latin1")
            )
        elif raw.startswith("/"):
            end = raw.rfind("/")
            flags = re.IGNORECASE if "i" in raw[end + 1 :] or "nocase" in modifiers else 0
            expression = re.compile(raw[1:end].encode(), flags)
        else:
            expression = _hex_regex(raw[1:-1])
        patterns.append(_Pattern(identifier, expression, modifiers, line))
    return _Rule(name, tuple(metadata), tuple(patterns), condition)


def _pattern_matches(pattern: _Pattern, data: bytes) -> list[_Match]:
    expressions: list[bytes | re.Pattern[bytes]] = [pattern.expression]
    if isinstance(pattern.expression, bytes) and "wide" in pattern.modifiers:
        wide = b"".join(bytes((byte, 0)) for byte in pattern.expression)
        expressions = [wide] + ([pattern.expression] if "ascii" in pattern.modifiers else [])
    output: list[_Match] = []
    for expression in expressions:
        if isinstance(expression, bytes):
            flags = re.IGNORECASE if "nocase" in pattern.modifiers else 0
            regex = re.compile(re.escape(expression), flags)
        else:
            regex = expression
        for match in regex.finditer(data):
            if "fullword" in pattern.modifiers:
                before = data[match.start() - 1 : match.start()]
                after = data[match.end() : match.end() + 1]
                if (before and (before.isalnum() or before == b"_")) or (
                    after and (after.isalnum() or after == b"_")
                ):
                    continue
            output.append(_Match(pattern.identifier, match.start(), match.group()))
    return sorted(output, key=lambda item: item.position)


def _balanced(expression: str) -> bool:
    depth = 0
    quote = ""
    for index, character in enumerate(expression):
        if quote:
            if character == quote and expression[index - 1] != "\\":
                quote = ""
        elif character in "'\"":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0 and index < len(expression) - 1:
                return False
    return depth == 0


def _split_boolean(expression: str, word: str) -> list[str]:
    depth = 0
    quote = ""
    for index, character in enumerate(expression):
        if quote:
            if character == quote and expression[index - 1] != "\\":
                quote = ""
        elif character in "'\"":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif depth == 0 and expression.startswith(word, index):
            return [expression[:index], expression[index + len(word) :]]
    return [expression]


def _condition(
    expression: str,
    data: bytes,
    matches: dict[str, list[_Match]],
    logs: list[str],
) -> bool:
    expression = expression.strip().rstrip(";")
    while expression.startswith("(") and expression.endswith(")") and _balanced(expression):
        expression = expression[1:-1].strip()
    for word in (" or ", " and "):
        split = _split_boolean(expression, word)
        if len(split) == 2:
            left = _condition(split[0], data, matches, logs)
            right = _condition(split[1], data, matches, logs)
            return left or right if word.strip() == "or" else left and right
    if expression.startswith("not "):
        return not _condition(expression[4:], data, matches, logs)
    console = re.fullmatch(
        r"console\.(log|hex)\(\s*\"([^\"]*)\"(?:\s*,\s*int8\(0\))?\s*\)", expression
    )
    if console:
        logs.append(
            console.group(2) + (f"0x{data[0]:02x}" if console.group(1) == "hex" and data else "")
        )
        return True
    hash_match = re.fullmatch(
        r"hash\.(md5|sha1|sha256)\(0\s*,\s*filesize\)\s*==\s*\"([0-9a-fA-F]+)\"", expression
    )
    if hash_match:
        return (
            hashlib.new(hash_match.group(1), data).hexdigest().lower()
            == hash_match.group(2).lower()
        )
    quantifier = re.fullmatch(r"(any|all|\d+)\s+of\s+(?:them|\(([^)]*)\))", expression)
    if quantifier:
        identifiers = list(matches)
        if quantifier.group(2):
            requested = [item.strip() for item in quantifier.group(2).split(",")]
            identifiers = [
                identifier
                for identifier in identifiers
                if any(
                    re.fullmatch(pattern.replace("*", ".*"), identifier) for pattern in requested
                )
            ]
        count = sum(bool(matches[identifier]) for identifier in identifiers)
        required = (
            len(identifiers)
            if quantifier.group(1) == "all"
            else 1
            if quantifier.group(1) == "any"
            else int(quantifier.group(1))
        )
        return count >= required
    position_match = re.fullmatch(r"(\$\w+)\s+at\s+(0x[0-9a-fA-F]+|\d+)", expression)
    if position_match:
        return any(
            item.position == int(position_match.group(2), 0)
            for item in matches.get(position_match.group(1), [])
        )
    range_match = re.fullmatch(r"(\$\w+)\s+in\s+\((\d+)\.\.(filesize|\d+)\)", expression)
    if range_match:
        end = len(data) if range_match.group(3) == "filesize" else int(range_match.group(3))
        return any(
            int(range_match.group(2)) <= item.position <= end
            for item in matches.get(range_match.group(1), [])
        )
    compare = re.fullmatch(
        r"(filesize|#\w+|uint(?:8|16|32)\(\d+\)|int(?:8|16|32)\(\d+\))\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|\d+)(KB|MB)?",
        expression,
    )
    if compare:
        left_name, operator, raw, unit = compare.groups()
        if left_name == "filesize":
            left = len(data)
        elif left_name.startswith("#"):
            left = len(matches.get("$" + left_name[1:], []))
        else:
            signed = left_name.startswith("int")
            width_match = re.search(r"\d+", left_name)
            offset_match = re.search(r"\((\d+)\)", left_name)
            if width_match is None or offset_match is None:
                raise ValueError("Invalid YARA integer expression")
            width = int(width_match.group()) // 8
            offset = int(offset_match.group(1))
            left = int.from_bytes(data[offset : offset + width], "little", signed=signed)
        right = int(raw, 0) * ({None: 1, "KB": 1024, "MB": 1024 * 1024}[unit])
        return {
            "==": left == right,
            "!=": left != right,
            "<=": left <= right,
            ">=": left >= right,
            "<": left < right,
            ">": left > right,
        }[operator]
    if expression in {"true", "false"}:
        return expression == "true"
    if re.fullmatch(r"\$\w+", expression):
        return bool(matches.get(expression))
    raise ValueError(f"unsupported condition: {expression}")


@implementation("YARA Rules", category="Yara")
def yara_rules(value: Data, args: Args) -> str:
    data = to_bytes(value)
    source = str(arg(args, 0, ""))
    show_strings = bool(arg(args, 1, False))
    show_lengths = bool(arg(args, 2, False))
    show_meta = bool(arg(args, 3, False))
    show_counts = bool(arg(args, 4, True))
    show_warnings = bool(arg(args, 5, True))
    show_console = bool(arg(args, 6, True))
    parsed = [_parse_rule(*rule) for rule in _rules(source)]
    warnings: list[str] = []
    logs: list[str] = []
    results: list[tuple[_Rule, list[_Match]]] = []
    for rule in parsed:
        by_identifier = {
            pattern.identifier: _pattern_matches(pattern, data) for pattern in rule.patterns
        }
        if show_warnings:
            for pattern in rule.patterns:
                if isinstance(pattern.expression, bytes) and len(pattern.expression) <= 1:
                    warning = (
                        f'Warning on line {pattern.line}: string "{pattern.identifier}" '
                        "may slow down scanning"
                    )
                    warnings.append(warning)
        if _condition(rule.condition, data, by_identifier, logs):
            results.append(
                (
                    rule,
                    sorted(
                        (match for group in by_identifier.values() for match in group),
                        key=lambda item: item.position,
                    ),
                )
            )
    output = [*warnings, *(logs if show_console else [])]
    for rule, resolved in results:
        meta = ""
        if show_meta and rule.metadata:
            meta = " [" + ", ".join(f"{key}: {value}" for key, value in rule.metadata) + "]"
        count = (
            f" ({len(resolved)} time{'s' if len(resolved) > 1 else ''})"
            if show_counts and resolved
            else ""
        )
        if not resolved or not (show_strings or show_lengths):
            output.append(f'Input matches rule "{rule.name}"{meta}{count}.')
            continue
        output.append(f'Rule "{rule.name}"{meta} matches{count}:')
        for match in resolved:
            detail = f"Pos {match.position}, "
            if show_lengths:
                detail += f"length {len(match.data)}, "
            detail += f"identifier {match.identifier}"
            if show_strings:
                detail += f', data: "{match.data.decode("latin1")}"'
            output.append(detail)
    return "\n".join(output) + ("\n" if output else "")
