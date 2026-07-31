"""Analysis, generation, formatting, and utility operations."""

from __future__ import annotations

import difflib
import html
import random
import re
import secrets
import time
from collections import Counter

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, require_int


@operation("Comment", category="Flow control")
@operation("Label", category="Flow control")
@operation("Return", category="Flow control")
def passthrough(value: Data, _args: Args) -> Data:
    return value


@operation("Sleep", category="Flow control")
def sleep(value: Data, args: Args) -> Data:
    milliseconds = require_int(arg(args, 0, 1000), name="time")
    if not 0 <= milliseconds <= 60_000:
        raise ValueError("sleep duration must be between 0 and 60000 milliseconds")
    time.sleep(milliseconds / 1000)
    return value


@operation("Get All Casings", category="Text")
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


@operation("Generate De Bruijn Sequence", category="Generators")
def de_bruijn(value: Data, args: Args) -> str:
    alphabet_size = require_int(arg(args, 0, 2), name="alphabet size")
    subsequence_length = require_int(arg(args, 1, 3), name="key length")
    alphabet = to_text(value) or "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    if not 1 <= alphabet_size <= len(alphabet) or subsequence_length < 1:
        raise ValueError("invalid De Bruijn parameters")
    symbols = alphabet[:alphabet_size]
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
    return "".join(symbols[index] for index in sequence)


_LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt "
    "ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco "
    "laboris nisi ut aliquip ex ea commodo consequat."
)


@operation("Generate Lorem Ipsum", category="Generators")
def lorem_ipsum(_value: Data, args: Args) -> str:
    length = require_int(arg(args, 0, 3), name="length")
    unit = str(arg(args, 1, "Paragraphs"))
    if unit == "Bytes":
        return (_LOREM * ((length // len(_LOREM)) + 1)).encode()[:length].decode("latin-1")
    if unit == "Words":
        words = (_LOREM.replace(".", "").split() * ((length // 30) + 1))[:length]
        return " ".join(words)
    if unit == "Sentences":
        sentences = [sentence.strip() + "." for sentence in _LOREM.split(".") if sentence.strip()]
        return " ".join((sentences * ((length // len(sentences)) + 1))[:length])
    return "\n\n".join([_LOREM] * length)


@operation("Pseudo-Random Number Generator", category="Generators")
def random_bytes(_value: Data, args: Args) -> Data:
    count = require_int(arg(args, 0, 32), name="number of bytes")
    output_format = str(arg(args, 1, "Hex"))
    if not 1 <= count <= 1_000_000:
        raise ValueError("number of random bytes is out of range")
    data = secrets.token_bytes(count)
    if output_format == "Hex":
        return data.hex()
    if output_format == "Integer":
        return str(int.from_bytes(data, "big"))
    if output_format == "Byte array":
        return " ".join(map(str, data))
    return data


@operation("Pseudo-Random Integer Generator", category="Generators")
def random_integers(_value: Data, args: Args) -> str:
    count = require_int(arg(args, 0, 1))
    minimum = require_int(arg(args, 1, 0))
    maximum = require_int(arg(args, 2, 99))
    delimiter = char_rep(arg(args, 3, "Line feed"), "\n")
    output_format = str(arg(args, 4, "Decimal"))
    if count < 1 or count > 1_000_000 or minimum > maximum:
        raise ValueError("invalid random integer parameters")
    values = [secrets.randbelow(maximum - minimum + 1) + minimum for _ in range(count)]
    if output_format == "Hex":
        return delimiter.join(f"{value:x}" for value in values)
    if output_format == "Raw":
        return bytes(value & 0xFF for value in values).decode("latin-1")
    return delimiter.join(map(str, values))


@operation("XKCD Random Number", category="Generators")
def xkcd_random(_value: Data, _args: Args) -> str:
    return "4"


@operation("Shuffle", category="Text")
def shuffle(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    items = to_text(value).split(delimiter)
    random.SystemRandom().shuffle(items)
    return delimiter.join(items)


@operation("Frequency distribution", category="Analysis")
def frequency_distribution(value: Data, args: Args) -> str:
    show_zero = bool(arg(args, 0, True))
    show_ascii = bool(arg(args, 1, True))
    counts = Counter(to_bytes(value))
    total = sum(counts.values()) or 1
    lines = ["Byte  Count  Percentage" + ("  ASCII" if show_ascii else "")]
    for byte in range(256):
        if not show_zero and not counts[byte]:
            continue
        line = f"{byte:02x}    {counts[byte]:5d}  {counts[byte] / total * 100:9.5f}%"
        if show_ascii:
            line += f"  {chr(byte) if 32 <= byte <= 126 else '.'}"
        lines.append(line)
    return "\n".join(lines)


@operation("Diff", category="Analysis")
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


@operation("Fuzzy Match", category="Analysis")
def fuzzy_match(value: Data, args: Args) -> str:
    search = str(arg(args, 0, ""))
    score = difflib.SequenceMatcher(None, search.casefold(), to_text(value).casefold()).ratio()
    return str(round(score * 100))


@operation("Extract dates", category="Extraction")
def extract_dates(value: Data, args: Args) -> str:
    pattern = re.compile(r"\b(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})\b")
    matches = pattern.findall(to_text(value))
    output = "\n".join(matches)
    return f"Total found: {len(matches)}\n\n{output}" if bool(arg(args, 0, False)) else output


@operation("Extract file paths", category="Extraction")
def extract_file_paths(value: Data, args: Args) -> str:
    matches: list[str] = []
    text = to_text(value)
    if bool(arg(args, 0, True)):
        matches.extend(re.findall(r"\b[A-Za-z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n\s]+", text))
    if bool(arg(args, 1, True)):
        matches.extend(re.findall(r"(?<!\w)/(?:[^/\s]+/)*[^/\s]+", text))
    if bool(arg(args, 4, False)):
        matches = list(dict.fromkeys(matches))
    if bool(arg(args, 3, False)):
        matches.sort()
    output = "\n".join(matches)
    return f"Total found: {len(matches)}\n\n{output}" if bool(arg(args, 2, False)) else output


@operation("Remove ANSI Escape Codes", category="Text")
def remove_ansi(value: Data, _args: Args) -> str:
    return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", to_text(value))


@operation("Escape Smart Characters", category="Text")
def escape_smart(value: Data, args: Args) -> str:
    mode = str(arg(args, 0, "Include"))
    replacements = {
        "\u201c": '"',
        "\u201d": '"',
        "\u2018": "'",
        "\u2019": "'",
        "\u2013": "-",
        "\u2014": "-",
        "\u2026": "...",
    }
    output = "".join(replacements.get(character, character) for character in to_text(value))
    if mode == "Remove":
        return output.encode("ascii", "ignore").decode()
    if mode == "Replace with '.'":
        return output.encode("ascii", "replace").decode().replace("?", ".")
    return output


@operation("Caret/M-decode", category="Encoding")
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


@operation("Substitute", category="Ciphers")
def substitute(value: Data, args: Args) -> str:
    plaintext = str(arg(args, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    ciphertext = str(arg(args, 1, "XYZABCDEFGHIJKLMNOPQRSTUVW"))
    ignore_case = bool(arg(args, 2, False))
    if len(plaintext) != len(ciphertext):
        raise ValueError("plaintext and ciphertext alphabets must have the same length")
    table = str.maketrans(plaintext, ciphertext)
    if ignore_case:
        table.update(str.maketrans(plaintext.lower(), ciphertext.lower()))
    return to_text(value).translate(table)


@operation("Template", category="Text")
def template(value: Data, args: Args) -> str:
    definition = str(arg(args, 0, ""))
    return definition.replace("{{this}}", to_text(value)).replace("{{{this}}}", to_text(value))


@operation("Offset checker", category="Analysis")
def offset_checker(value: Data, args: Args) -> str:
    delimiter = str(arg(args, 0, "\\n\\n")).replace("\\n", "\n")
    left, separator, right = to_text(value).partition(delimiter)
    if not separator:
        raise ValueError("input does not contain the sample delimiter")
    offsets = [index for index in range(min(len(left), len(right))) if left[index] != right[index]]
    return "\n".join(map(str, offsets))


def _rows(value: Data, cell_delimiter: str, row_delimiter: str) -> list[list[str]]:
    return [row.split(cell_delimiter) for row in to_text(value).split(row_delimiter)]


@operation("To Table", category="Text")
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
    text = to_text(value)
    if not preserve_comments:
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"//[^\r\n]*", "", text)
    return re.sub(r"\s*([{};,:>+~=])\s*", r"\1", re.sub(r"\s+", " ", text)).strip()


def _beautify_code(value: Data, indent: str) -> str:
    text = _minify_code(value, preserve_comments=True)
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
    return "".join(output).strip()


@operation("CSS Minify", category="Code")
def css_minify(value: Data, args: Args) -> str:
    return _minify_code(value, bool(arg(args, 0, False)))


@operation("CSS Beautify", category="Code")
def css_beautify(value: Data, args: Args) -> str:
    return _beautify_code(value, str(arg(args, 0, "\\t")).replace("\\t", "\t"))


@operation("JavaScript Minify", category="Code")
@operation("SQL Minify", category="Code")
def code_minify(value: Data, _args: Args) -> str:
    return _minify_code(value)


@operation("JavaScript Beautify", category="Code")
@operation("SQL Beautify", category="Code")
def code_beautify(value: Data, args: Args) -> str:
    return _beautify_code(value, str(arg(args, 0, "\\t")).replace("\\t", "\t"))


@operation("Generic Code Beautify", category="Code")
def generic_beautify(value: Data, _args: Args) -> str:
    return _beautify_code(value, "    ")


@operation("Numberwang", category="Miscellaneous")
def numberwang(value: Data, _args: Args) -> str:
    text = to_text(value)
    if not text:
        result = "Let's play Wangernumb!"
    elif re.search(r"-?√?\d+(?:\.\d+)?i?(?:[a-z]?)%?", text, re.I):
        result = f"{text}! That's Numberwang!"
    else:
        result = "Sorry, that's not Numberwang. Let's rotate the board!"
    return result + "\n\nDid you know: The 6705th digit of pi is Numberwang."
