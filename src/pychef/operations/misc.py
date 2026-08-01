"""Analysis, generation, formatting, and utility operations."""

from __future__ import annotations

import difflib
import html
import json
import random
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from typing import Any

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, expand_alphabet, require_int


@implementation("Comment", category="Flow control")
@implementation("Label", category="Flow control")
@implementation("Return", category="Flow control")
def passthrough(value: Data, _args: Args) -> Data:
    return value


@implementation("Sleep", category="Flow control")
def sleep(value: Data, args: Args) -> Data:
    milliseconds = require_int(arg(args, 0, 1000), name="time")
    if not 0 <= milliseconds <= 60_000:
        raise ValueError("sleep duration must be between 0 and 60000 milliseconds")
    time.sleep(milliseconds / 1000)
    return value


@implementation("Get All Casings", category="Text")
def get_all_casings(value: Data, _args: Args) -> str:
    text = to_text(value).lower()
    if len(text) > 20:
        raise ValueError("input is too long to enumerate every casing safely")
    return "\n".join(
        "".join(
            character.upper() if mask & (1 << index) else character
            for index, character in enumerate(text)
        )
        for mask in range(1 << len(text))
    )


@implementation("Generate De Bruijn Sequence", category="Generators")
def de_bruijn(_value: Data, args: Args) -> str:
    alphabet_size = require_int(arg(args, 0, 2), name="alphabet size")
    subsequence_length = require_int(arg(args, 1, 3), name="key length")
    if not 2 <= alphabet_size <= 9:
        raise ValueError("alphabet size must be between 2 and 9")
    if subsequence_length < 2:
        raise ValueError("key length must be at least 2")
    if alphabet_size**subsequence_length > 50_000:
        raise ValueError("too many permutations; alphabet_size ** key_length must not exceed 50000")
    work = [0] * (alphabet_size * subsequence_length)
    sequence: list[int] = []

    def visit(order: int, period: int) -> None:
        if order > subsequence_length:
            if subsequence_length % period == 0:
                sequence.extend(work[1 : period + 1])
            return
        work[order] = work[order - period]
        visit(order + 1, period)
        for symbol in range(work[order - period] + 1, alphabet_size):
            work[order] = symbol
            visit(order + 1, order)

    visit(1, 1)
    return "".join(map(str, sequence))


_LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt "
    "ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco "
    "laboris nisi ut aliquip ex ea commodo consequat."
)


@implementation("Generate Lorem Ipsum", category="Generators")
def lorem_ipsum(_value: Data, args: Args) -> str:
    length = require_int(arg(args, 0, 3), name="length")
    unit = str(arg(args, 1, "Paragraphs"))
    if length < 1:
        raise ValueError("length must be greater than 0")
    if unit not in {"Paragraphs", "Sentences", "Words", "Bytes"}:
        raise ValueError("length unit must be Paragraphs, Sentences, Words, or Bytes")
    maximum = 1_000_000 if unit == "Bytes" else 100_000
    if length > maximum:
        raise ValueError(f"length must be less than {maximum}")
    if unit == "Bytes":
        return (_LOREM * ((length // len(_LOREM)) + 1)).encode()[:length].decode("latin-1")
    if unit == "Words":
        words = (_LOREM.replace(".", "").split() * ((length // 30) + 1))[:length]
        return " ".join(words)
    if unit == "Sentences":
        sentences = [sentence.strip() + "." for sentence in _LOREM.split(".") if sentence.strip()]
        return " ".join((sentences * ((length // len(sentences)) + 1))[:length])
    return "\n\n".join([_LOREM] * length)


@implementation("Pseudo-Random Number Generator", category="Generators")
def random_bytes(_value: Data, args: Args) -> Data:
    count = require_int(arg(args, 0, 32), name="number of bytes")
    output_format = str(arg(args, 1, "Hex"))
    if not 1 <= count <= 1_000_000:
        raise ValueError("number of random bytes is out of range")
    data = secrets.token_bytes(count)
    if output_format == "Hex":
        return data.hex()
    if output_format == "Integer":
        return str(int.from_bytes(data, "little"))
    if output_format == "Byte array":
        return json.dumps(list(data), separators=(",", ":"))
    return data


@implementation("Pseudo-Random Integer Generator", category="Generators")
def random_integers(_value: Data, args: Args) -> str:
    count = require_int(arg(args, 0, 1))
    minimum = require_int(arg(args, 1, 0))
    maximum = require_int(arg(args, 2, 99))
    delimiter = char_rep(arg(args, 3, "Space"), " ")
    output_format = str(arg(args, 4, "Decimal"))
    safe_limit = 2**53 - 1
    if (
        count < 1
        or count > 1_000_000
        or minimum > maximum
        or not -safe_limit <= minimum <= safe_limit
        or not -safe_limit <= maximum <= safe_limit
        or maximum - minimum + 1 > safe_limit
    ):
        raise ValueError("invalid random integer parameters")
    values = [secrets.randbelow(maximum - minimum + 1) + minimum for _ in range(count)]
    if output_format == "Hex":
        return delimiter.join(f"{value:x}" for value in values)
    if output_format == "Raw":
        return "".join(chr(value % 65536) for value in values)
    return delimiter.join(map(str, values))


@implementation("XKCD Random Number", category="Generators")
def xkcd_random(_value: Data, _args: Args) -> str:
    return "4"


@implementation("Shuffle", category="Text")
def shuffle(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    items = to_text(value).split(delimiter)
    random.SystemRandom().shuffle(items)
    return delimiter.join(items)


@implementation("Frequency distribution", category="Analysis")
def frequency_distribution(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    if not data:
        raise ValueError("No data")
    distribution = [0] * 256
    for byte in data:
        distribution[byte] += 1
    result = {
        "dataLength": len(data),
        "percentages": [count / len(data) * 100 for count in distribution],
        "distribution": distribution,
        "bytesRepresented": sum(count > 0 for count in distribution),
    }
    return json.dumps(result, separators=(",", ":"))


@implementation("Diff", category="Analysis")
def diff(value: Data, args: Args) -> str:
    delimiter = str(arg(args, 0, "\\n\\n")).replace("\\n", "\n")
    mode = str(arg(args, 1, "Character"))
    left, separator, right = to_text(value).partition(delimiter)
    if not separator:
        raise ValueError("input does not contain the sample delimiter")
    if mode == "Line":
        left_parts, right_parts = left.splitlines(keepends=True), right.splitlines(keepends=True)
    elif mode == "Word":
        left_parts, right_parts = left.split(), right.split()
    else:
        left_parts, right_parts = list(left), list(right)
    return "".join(difflib.ndiff(left_parts, right_parts))


@implementation("Fuzzy Match", category="Analysis")
def fuzzy_match(value: Data, args: Args) -> str:
    text = to_text(value)
    pattern = str(arg(args, 0, ""))
    weights = tuple(
        float(arg(args, index, default))
        for index, default in enumerate((15, 30, 30, 15, -5, -15, -1), start=1)
    )
    matches: list[list[int]] = []
    start = 0
    while pattern and start < len(text):
        indexes = _best_fuzzy_indexes(pattern, text, start, weights)
        if not indexes:
            break
        matches.append(indexes)
        start = indexes[-1] + 1
    if not matches:
        return html.escape(text)

    output: list[str] = []
    position = 0
    for match_index, indexes in enumerate(matches):
        ranges: list[tuple[int, int]] = []
        for index in indexes:
            if ranges and index == ranges[-1][1]:
                ranges[-1] = ranges[-1][0], index + 1
            else:
                ranges.append((index, index + 1))
        for range_index, (range_start, range_end) in enumerate(ranges):
            output.append(html.escape(text[position:range_start]))
            if range_index == 0:
                output.append(f'<span class="hl{1 + match_index % 2}">')
            output.append(f"<b>{html.escape(text[range_start:range_end])}</b>")
            position = range_end
        output.append("</span>")
    output.append(html.escape(text[position:]))
    return "".join(output)


def _best_fuzzy_indexes(
    pattern: str, text: str, start: int, weights: tuple[float, ...]
) -> list[int]:
    sequential, separator, camel, first_letter, leading, max_leading, _unmatched = weights
    folded_pattern = pattern.lower()
    folded_text = text.lower()

    def position_bonus(index: int) -> float:
        if index == 0:
            return first_letter
        previous, current = text[index - 1], text[index]
        bonus = separator if previous in {"_", " "} else 0
        if previous != previous.upper() and current != current.lower():
            bonus += camel
        return bonus

    scores: dict[int, tuple[float, list[int]]] = {}
    for index in range(start, len(text)):
        if folded_text[index] == folded_pattern[0]:
            penalty = max(leading * index, max_leading)
            scores[index] = penalty + position_bonus(index), [index]
    for character in folded_pattern[1:]:
        next_scores: dict[int, tuple[float, list[int]]] = {}
        best_before: tuple[float, list[int]] | None = None
        for index in range(start, len(text)):
            previous = scores.get(index - 1)
            if previous is not None and (best_before is None or previous[0] > best_before[0]):
                best_before = previous
            if folded_text[index] != character or best_before is None:
                continue
            best_score, best_indexes = best_before
            adjacent = scores.get(index - 1)
            if adjacent is not None and adjacent[0] + sequential > best_score:
                best_score, best_indexes = adjacent[0] + sequential, adjacent[1]
            next_scores[index] = best_score + position_bonus(index), [*best_indexes, index]
        scores = next_scores
        if not scores:
            return []
    return max(scores.values(), key=lambda result: result[0])[1] if scores else []


@implementation("Extract dates", category="Extraction")
def extract_dates(value: Data, args: Args) -> str:
    year = r"(?:19|20)\d\d"
    month = r"(?:0[1-9]|1[012])"
    day = r"(?:0[1-9]|[12][0-9]|3[01])"
    divider = r"[- /.]"
    pattern = re.compile(
        rf"{year}{divider}{month}{divider}{day}|"
        rf"{day}{divider}{month}{divider}{year}|"
        rf"{month}{divider}{day}{divider}{year}",
        re.IGNORECASE,
    )
    matches = pattern.findall(to_text(value))
    output = "\n".join(matches)
    return f"Total found: {len(matches)}\n\n{output}" if bool(arg(args, 0, False)) else output


@implementation("Extract file paths", category="Extraction")
def extract_file_paths(value: Data, args: Args) -> str:
    patterns: list[str] = []
    text = to_text(value)
    if bool(arg(args, 0, True)):
        windows_name = r"[A-Z\d][A-Z\d\- '_()~]{0,61}"
        patterns.append(rf"[A-Z]:\\(?:{windows_name}\\?)*{windows_name}(?:\.[A-Z\d]{{1,6}})?")
    if bool(arg(args, 1, True)):
        patterns.append(r"(?:/[A-Z\d.][A-Z\d\-.]{0,61})+")
    if not patterns:
        return ""
    matches = re.findall("|".join(f"(?:{pattern})" for pattern in patterns), text, re.IGNORECASE)
    if bool(arg(args, 4, False)):
        matches = list(dict.fromkeys(matches))
    if bool(arg(args, 3, False)):
        matches.sort(key=str.casefold)
    output = "\n".join(matches)
    return f"Total found: {len(matches)}\n\n{output}" if bool(arg(args, 2, False)) else output


@implementation("Remove ANSI Escape Codes", category="Text")
def remove_ansi(value: Data, _args: Args) -> str:
    return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", to_text(value))


@implementation("Escape Smart Characters", category="Text")
def escape_smart(value: Data, args: Args) -> str:
    mode = str(arg(args, 0, "Include"))
    replacements = {
        "\u201c": '"',
        "\u201d": '"',
        "\u201e": '"',
        "\u201f": '"',
        "\u2033": '"',
        "\u2018": "'",
        "\u2019": "'",
        "\u201a": "'",
        "\u201b": "'",
        "\u2032": "'",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "--",
        "\u2015": "--",
        "\u2026": "...",
        "©": "(c)",
        "®": "(r)",
        "™": "(tm)",
        "←": "<--",
        "→": "-->",
        "↑": "^",
        "↓": "v",
        "↔": "<->",
        "⇐": "<==",
        "⇒": "==>",
        "⇔": "<=>",
        "«": "<<",
        "»": ">>",
        "\u2039": "<",
        "\u203a": ">",
        "\u00d7": "x",
        "÷": "/",
        "±": "+/-",
        "•": "*",
        "·": ".",
        "\u00a0": " ",
        "\u2002": " ",
        "\u2003": " ",
        "\u2009": " ",
        "\u200a": " ",
    }
    output: list[str] = []
    for character in to_text(value):
        if ord(character) < 128 or character in replacements:
            output.append(replacements.get(character, character))
        elif mode == "Remove":
            continue
        elif mode == "Replace with '.'":
            output.append(".")
        else:
            output.append(character)
    return "".join(output)


@implementation("Caret/M-decode", category="Encoding")
def caret_m_decode(value: Data, _args: Args) -> bytes:
    text = to_text(value)
    output = bytearray()
    index = 0
    while index < len(text):
        if text.startswith("M-^", index) and index + 3 < len(text):
            code = ord(text[index + 3])
            output.append(255 if code == 63 else code + 64)
            index += 4
        elif text.startswith("M-", index) and index + 2 < len(text):
            output.append(ord(text[index + 2]) + 128)
            index += 3
        elif text[index] == "^" and index + 1 < len(text):
            code = ord(text[index + 1])
            output.append(127 if code == 63 else code - 64)
            index += 2
        else:
            output.append(ord(text[index]) & 0xFF)
            index += 1
    return bytes(output)


@implementation("Substitute", category="Ciphers")
def substitute(value: Data, args: Args) -> str:
    from .text import _escaped

    plaintext = expand_alphabet(_escaped(arg(args, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")))
    ciphertext = expand_alphabet(_escaped(arg(args, 1, "XYZABCDEFGHIJKLMNOPQRSTUVW")))
    ignore_case = bool(arg(args, 2, False))
    substitutions = dict(zip(plaintext, ciphertext, strict=False))
    output = (
        "Warning: Plaintext and Ciphertext lengths differ\n\n"
        if len(plaintext) != len(ciphertext)
        else ""
    )
    for character in to_text(value):
        replacement = substitutions.get(character)
        if replacement is None and ignore_case:
            replacement = substitutions.get(character.swapcase())
        if replacement is None:
            output += character
        elif ignore_case and character.isupper():
            output += replacement.upper()
        elif ignore_case and character.islower():
            output += replacement.lower()
        else:
            output += replacement
    return output


@implementation("Template", category="Text")
def template(value: Data, args: Args) -> str:
    definition = str(arg(args, 0, ""))
    try:
        context = json.loads(to_text(value))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON input: {exc.msg}") from exc
    partials: dict[str, str] = {}
    inline = re.compile(
        r'(?m)^[ \t]*{{#\*inline\s+["\']([^"\']+)["\']}}[ \t]*\r?\n?'
        r"(.*?)^[ \t]*{{/inline}}[ \t]*\r?\n?",
        re.DOTALL,
    )

    def remember(match: re.Match[str]) -> str:
        partials[match.group(1)] = match.group(2)
        return ""

    definition = inline.sub(remember, definition)
    return _render_template(definition, context, context, partials, (), {})


_TEMPLATE_TOKEN = re.compile(r"{{{.*?}}}|{{.*?}}", re.DOTALL)


def _template_lookup(
    path: str, context: Any, root: Any, parents: tuple[Any, ...], locals_: Mapping[str, Any]
) -> Any:
    path = path.strip()
    if path in {"", ".", "this"}:
        return context
    if path.startswith("@root"):
        context, path = root, path[5:].lstrip("./")
    elif path.startswith("@"):
        head, _, tail = path.partition(".")
        context = locals_.get(head, "")
        path = tail
    else:
        while path.startswith("../"):
            context = parents[-1] if parents else root
            parents = parents[:-1]
            path = path[3:]
        if path.startswith("this."):
            path = path[5:]
    for part in filter(None, re.split(r"[./]", path)):
        if isinstance(context, Mapping):
            context = context.get(part, "")
        elif isinstance(context, Sequence) and not isinstance(context, (str, bytes, bytearray)):
            try:
                context = context[int(part)]
            except (ValueError, IndexError):
                return ""
        else:
            return ""
    return context


def _template_text(value: Any) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _template_escape(value: Any) -> str:
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "`": "&#x60;",
        "=": "&#x3D;",
    }
    return "".join(replacements.get(character, character) for character in _template_text(value))


def _template_block_end(template: str, start: int, name: str) -> tuple[int, int]:
    depth = 1
    for token in _TEMPLATE_TOKEN.finditer(template, start):
        expression = token.group(0)[2:-2].strip()
        if expression.startswith(f"#{name} ") or expression == f"#{name}":
            depth += 1
        elif expression == f"/{name}":
            depth -= 1
            if depth == 0:
                return token.start(), token.end()
    raise ValueError(f"unclosed template block: {name}")


def _render_template(
    definition: str,
    context: Any,
    root: Any,
    partials: Mapping[str, str],
    parents: tuple[Any, ...],
    locals_: Mapping[str, Any],
) -> str:
    output: list[str] = []
    position = 0
    while match := _TEMPLATE_TOKEN.search(definition, position):
        output.append(definition[position : match.start()])
        token = match.group(0)
        triple = token.startswith("{{{")
        expression = token[3:-3].strip() if triple else token[2:-2].strip()
        if expression.startswith("#"):
            command, _, path = expression[1:].partition(" ")
            if command not in {"each", "if", "unless"}:
                raise ValueError(f"unsupported template block: {command}")
            body_end, block_end = _template_block_end(definition, match.end(), command)
            body = definition[match.end() : body_end]
            if body.startswith("\r\n"):
                body = body[2:]
            elif body.startswith("\n"):
                body = body[1:]
            selected = _template_lookup(path, context, root, parents, locals_)
            if command == "each" and isinstance(selected, Mapping):
                items = list(selected.items())
                for index, (key, item) in enumerate(items):
                    block_locals = {
                        "@index": index,
                        "@key": key,
                        "@first": index == 0,
                        "@last": index == len(items) - 1,
                    }
                    output.append(
                        _render_template(
                            body, item, root, partials, (*parents, context), block_locals
                        )
                    )
            elif (
                command == "each"
                and isinstance(selected, Sequence)
                and not isinstance(selected, (str, bytes, bytearray))
            ):
                for index, item in enumerate(selected):
                    block_locals = {
                        "@index": index,
                        "@first": index == 0,
                        "@last": index == len(selected) - 1,
                    }
                    output.append(
                        _render_template(
                            body, item, root, partials, (*parents, context), block_locals
                        )
                    )
            elif command in {"if", "unless"} and (bool(selected) == (command == "if")):
                output.append(_render_template(body, context, root, partials, parents, locals_))
            position = block_end
            if definition[position : position + 2] == "\r\n":
                position += 2
            elif definition[position : position + 1] == "\n":
                position += 1
            continue
        if expression.startswith("/"):
            raise ValueError(f"unexpected template closing block: {expression}")
        if expression.startswith("!"):
            rendered = ""
        elif expression.startswith(">"):
            name = expression[1:].strip()
            rendered = _render_template(
                partials.get(name, ""), context, root, partials, parents, locals_
            )
        else:
            selected = _template_lookup(expression, context, root, parents, locals_)
            rendered = (
                _template_text(selected)
                if triple or expression.startswith("& ")
                else _template_escape(selected)
            )
        output.append(rendered)
        position = match.end()
        if (
            expression.startswith(">")
            and not definition[definition.rfind("\n", 0, match.start()) + 1 : match.start()].strip()
        ):
            if definition[position : position + 2] == "\r\n":
                position += 2
            elif definition[position : position + 1] == "\n":
                position += 1
    output.append(definition[position:])
    return "".join(output)


@implementation("Offset checker", category="Analysis")
def offset_checker(value: Data, args: Args) -> str:
    delimiter = str(arg(args, 0, "\\n\\n")).replace("\\r", "\r").replace("\\n", "\n")
    samples = to_text(value).split(delimiter)
    if len(samples) < 2:
        raise ValueError("not enough samples; check the sample delimiter")
    common = [
        all(index < len(sample) and sample[index] == character for sample in samples[1:])
        for index, character in enumerate(samples[0])
    ]
    rendered: list[str] = []
    for sample in samples:
        output: list[str] = []
        in_match = False
        for index, character in enumerate(sample):
            is_match = index < len(common) and common[index]
            if is_match and not in_match:
                output.append("<span class='hl5'>")
            elif not is_match and in_match:
                output.append("</span>")
            output.append(html.escape(character))
            in_match = is_match
        if in_match:
            output.append("</span>")
        rendered.append("".join(output))
    return html.escape(delimiter).join(rendered)


def _rows(value: Data, cell_delimiter: str, row_delimiter: str) -> list[list[str]]:
    return [row.split(cell_delimiter) for row in to_text(value).split(row_delimiter)]


@implementation("To Table", category="Text")
def to_table(value: Data, args: Args) -> str:
    cell_delimiter = str(arg(args, 0, ","))
    row_delimiter = str(arg(args, 1, "\\r\\n")).replace("\\r", "\r").replace("\\n", "\n")
    header = bool(arg(args, 2, False))
    output_format = str(arg(args, 3, "ASCII"))
    rows = _rows(value, cell_delimiter, row_delimiter)
    if output_format == "HTML":
        tags = []
        for index, row in enumerate(rows):
            tag = "th" if header and index == 0 else "td"
            tags.append(
                "<tr>" + "".join(f"<{tag}>{html.escape(cell)}</{tag}>" for cell in row) + "</tr>"
            )
        return "<table>\n" + "\n".join(tags) + "\n</table>"
    if output_format == "Markdown":
        lines = ["| " + " | ".join(row) + " |" for row in rows]
        if header and rows:
            lines.insert(1, "| " + " | ".join("---" for _ in rows[0]) + " |")
        return "\n".join(lines)
    widths = [
        max(len(row[index]) if index < len(row) else 0 for row in rows)
        for index in range(max(map(len, rows)))
    ]
    return "\n".join(
        " | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)) for row in rows
    )


def _minify_code(value: Data, preserve_comments: bool = False) -> str:
    text, protected = _protect_code(to_text(value), preserve_comments)
    text = re.sub(r"\s*([{};,:>+~=])\s*", r"\1", re.sub(r"\s+", " ", text)).strip()
    for marker, original in protected.items():
        text = text.replace(marker, original)
    return text


def _protect_code(text: str, preserve_comments: bool) -> tuple[str, dict[str, str]]:
    output: list[str] = []
    protected: dict[str, str] = {}
    index = 0

    def store(original: str) -> None:
        marker = f"\ue000{len(protected)}\ue001"
        protected[marker] = original
        output.append(marker)

    while index < len(text):
        if text[index] in {"'", '"', "`"}:
            quote = text[index]
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif end < len(text) and text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            store(text[index:end])
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            if preserve_comments:
                store(text[index:end])
            else:
                output.append(" ")
            index = end
        elif text.startswith("//", index):
            end = next(
                (position for position in range(index + 2, len(text)) if text[position] in "\r\n"),
                len(text),
            )
            if preserve_comments:
                store(text[index:end])
            else:
                output.append(" ")
            index = end
        else:
            output.append(text[index])
            index += 1
    return "".join(output), protected


def _beautify_code(value: Data, indent: str) -> str:
    masked, protected = _protect_code(to_text(value), True)
    text = re.sub(r"\s*([{};,:>+~=])\s*", r"\1", re.sub(r"\s+", " ", masked)).strip()
    output: list[str] = []
    level = 0
    for character in text:
        if character == "{":
            output.append(" {\n")
            level += 1
            output.append(indent * level)
        elif character == "}":
            level = max(0, level - 1)
            output.append("\n" + indent * level + "}")
        elif character == ";":
            output.append(";\n" + indent * level)
        else:
            output.append(character)
    rendered = "".join(output).strip()
    for marker, original in protected.items():
        rendered = rendered.replace(marker, original)
    return rendered


@implementation("CSS Minify", category="Code")
def css_minify(value: Data, args: Args) -> str:
    return _minify_code(value, bool(arg(args, 0, False)))


@implementation("CSS Beautify", category="Code")
def css_beautify(value: Data, args: Args) -> str:
    return _beautify_code(value, str(arg(args, 0, "\\t")).replace("\\t", "\t"))


@implementation("JavaScript Minify", category="Code")
def code_minify(value: Data, _args: Args) -> str:
    return _minify_code(value)


@implementation("JavaScript Beautify", category="Code")
def code_beautify(value: Data, args: Args) -> str:
    return _beautify_code(value, str(arg(args, 0, "\\t")).replace("\\t", "\t"))


_SQL_TOKEN = re.compile(
    r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|--[^\r\n]*|/\*.*?\*/|"
    r":\w+|[A-Za-z_][\w$]*|\d+(?:\.\d+)?|<>|!=|<=|>=|:=|[(),;.*=+\-/]|[^\s]",
    re.DOTALL,
)
_SQL_CLAUSES = (
    ("ON", "DUPLICATE", "KEY", "UPDATE"),
    ("INSERT", "INTO"),
    ("GROUP", "BY"),
    ("ORDER", "BY"),
    ("UNION", "ALL"),
    ("LEFT", "JOIN"),
    ("RIGHT", "JOIN"),
    ("INNER", "JOIN"),
    ("OUTER", "JOIN"),
    ("SELECT",),
    ("FROM",),
    ("WHERE",),
    ("HAVING",),
    ("LIMIT",),
    ("VALUES",),
    ("SET",),
    ("JOIN",),
)


def _sql_tokens(value: Data) -> list[str]:
    return [
        token for token in _SQL_TOKEN.findall(to_text(value)) if not token.startswith(("--", "/*"))
    ]


def _sql_clause(tokens: list[str], index: int) -> tuple[str, int] | None:
    for clause in _SQL_CLAUSES:
        if tuple(token.upper() for token in tokens[index : index + len(clause)]) == clause:
            return " ".join(tokens[index : index + len(clause)]), len(clause)
    return None


def _append_sql_token(current: str, token: str) -> str:
    if not current:
        return token
    if token in {",", ";", ")", "."} or current.endswith(("(", ".")):
        return current + token
    if token == "(" and (current[-1].isalnum() or current[-1] in {"_", "$"}):
        return current + token
    return current + " " + token


@implementation("SQL Minify", category="Code")
def sql_minify(value: Data, _args: Args) -> str:
    current = ""
    for token in _sql_tokens(value):
        current = _append_sql_token(current, token)
    return current


@implementation("SQL Beautify", category="Code")
def sql_beautify(value: Data, args: Args) -> str:
    indent = str(arg(args, 0, "\\t")).replace("\\t", "\t") or "    "
    tokens = _sql_tokens(value)
    lines: list[tuple[int, str]] = []
    current = ""
    current_indent = 0
    level = 0
    content_indent = 0
    list_mode = False
    parentheses: list[tuple[int, int]] = []

    def flush() -> None:
        nonlocal current
        if current:
            lines.append((current_indent, current))
            current = ""

    index = 0
    while index < len(tokens):
        clause = _sql_clause(tokens, index)
        if clause:
            text, consumed = clause
            flush()
            lines.append((level, text))
            current_indent = level + 1
            content_indent = current_indent
            list_mode = text.upper() in {"SELECT", "ON DUPLICATE KEY UPDATE", "SET"}
            index += consumed
            continue
        token = tokens[index]
        if token == "(" and _sql_clause(tokens, index + 1) == (tokens[index + 1], 1):
            current = _append_sql_token(current, token)
            paren_indent = current_indent
            flush()
            parentheses.append((level, paren_indent))
            level = paren_indent + 1
            current_indent = level
            index += 1
            continue
        if token == ")" and parentheses:
            flush()
            level, current_indent = parentheses.pop()
            current = ")"
            list_mode = False
            index += 1
            continue
        if token == "," and list_mode:
            current = _append_sql_token(current, token)
            flush()
            current_indent = content_indent
            index += 1
            continue
        current = _append_sql_token(current, token)
        index += 1
    flush()
    return "\n".join(indent * line_indent + line for line_indent, line in lines)


@implementation("Generic Code Beautify", category="Code")
def generic_beautify(value: Data, _args: Args) -> str:
    return _beautify_code(value, "    ")


@implementation("Numberwang", category="Miscellaneous")
def numberwang(value: Data, _args: Args) -> str:
    text = to_text(value)
    if not text:
        result = "Let's play Wangernumb!"
    elif re.search(r"-?√?\d+(?:\.\d+)?i?(?:[a-z]?)%?", text, re.I):
        result = f"{text}! That's Numberwang!"
    else:
        result = "Sorry, that's not Numberwang. Let's rotate the board!"
    return result + "\n\nDid you know: The 6705th digit of pi is Numberwang."
