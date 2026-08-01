"""Text, sequence, extraction, and byte-slicing operations."""

from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from collections import Counter
from collections.abc import Callable
from email.header import decode_header
from html.parser import HTMLParser
from itertools import chain, combinations, product
from typing import Literal, cast

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, expand_alphabet, require_int


def _escaped(value: object) -> str:
    text = str(value)
    output: list[str] = []
    index = 0
    simple = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "'": "'",
        '"': '"',
        "\\": "\\",
    }
    while index < len(text):
        if text[index] != "\\" or index + 1 >= len(text):
            output.append(text[index])
            index += 1
            continue
        marker = text[index + 1]
        if marker in simple:
            output.append(simple[marker])
            index += 2
        elif marker == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", text[index + 2 : index + 4]):
            output.append(chr(int(text[index + 2 : index + 4], 16)))
            index += 4
        elif marker == "u" and index + 2 < len(text) and text[index + 2] == "{":
            closing = text.find("}", index + 3)
            digits = text[index + 3 : closing] if closing >= 0 else ""
            if closing >= 0 and re.fullmatch(r"[0-9a-fA-F]{1,6}", digits):
                ordinal = int(digits, 16)
                if ordinal <= 0x10FFFF:
                    output.append(chr(ordinal))
                    index = closing + 1
                    continue
            output.append("\\")
            index += 1
        elif marker == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", text[index + 2 : index + 6]):
            ordinal = int(text[index + 2 : index + 6], 16)
            if 0xD800 <= ordinal <= 0xDBFF and re.fullmatch(
                r"\\u[0-9a-fA-F]{4}", text[index + 6 : index + 12]
            ):
                low = int(text[index + 8 : index + 12], 16)
                if 0xDC00 <= low <= 0xDFFF:
                    output.append(chr(0x10000 + ((ordinal - 0xD800) << 10) + low - 0xDC00))
                    index += 12
                    continue
            output.append(chr(ordinal))
            index += 6
        elif marker in "01234567":
            match = re.match(r"[0-7]{1,3}", text[index + 1 :])
            assert match is not None
            output.append(chr(int(match.group(0), 8)))
            index += 1 + len(match.group(0))
        else:
            output.append(marker)
            index += 2
    return "".join(output)


@implementation("Reverse", category="Data format")
def reverse(value: Data, args: Args) -> bytes:
    mode = str(arg(args, 0, "Character"))
    if mode == "Byte":
        return to_bytes(value)[::-1]
    text = to_text(value)
    if mode == "Line":
        return "\n".join(reversed(text.split("\n"))).encode()
    return "".join(reversed(text)).encode()


def _slice_lines(data: bytes, transform: Callable[[bytes], bytes]) -> bytes:
    return b"\n".join(transform(line) for line in data.split(b"\n"))


@implementation("Take bytes", category="Data format")
def take_bytes(value: Data, args: Args) -> bytes:
    start = require_int(arg(args, 0, 0))
    length = require_int(arg(args, 1, 5))
    data = to_bytes(value)
    transform = lambda item: item[start : start + length]  # noqa: E731
    return _slice_lines(data, transform) if bool(arg(args, 2, False)) else transform(data)


@implementation("Drop bytes", category="Data format")
def drop_bytes(value: Data, args: Args) -> bytes:
    start = require_int(arg(args, 0, 0))
    length = require_int(arg(args, 1, 5))
    data = to_bytes(value)
    transform = lambda item: item[:start] + item[start + length :]  # noqa: E731
    return _slice_lines(data, transform) if bool(arg(args, 2, False)) else transform(data)


@implementation("Take nth bytes", category="Data format")
def take_nth_bytes(value: Data, args: Args) -> bytes:
    every = require_int(arg(args, 0, 4), name="take every")
    start = require_int(arg(args, 1, 0), name="starting at")
    if every < 1:
        raise ValueError("take every must be positive")
    data = to_bytes(value)
    transform = lambda item: item[start::every]  # noqa: E731
    return _slice_lines(data, transform) if bool(arg(args, 2, False)) else transform(data)


@implementation("Drop nth bytes", category="Data format")
def drop_nth_bytes(value: Data, args: Args) -> bytes:
    every = require_int(arg(args, 0, 4), name="drop every")
    start = require_int(arg(args, 1, 0), name="starting at")
    if every < 1:
        raise ValueError("drop every must be positive")

    def transform(item: bytes) -> bytes:
        return bytes(
            byte for index, byte in enumerate(item) if index < start or (index - start) % every
        )

    data = to_bytes(value)
    return _slice_lines(data, transform) if bool(arg(args, 2, False)) else transform(data)


@implementation("Remove null bytes", category="Data format")
def remove_null_bytes(value: Data, _args: Args) -> bytes:
    return to_bytes(value).replace(b"\0", b"")


@implementation("Swap endianness", category="Data format")
def swap_endianness(value: Data, args: Args) -> Data:
    data_format = str(arg(args, 0, "Hex"))
    word_length = require_int(arg(args, 1, 4), name="word length")
    pad = bool(arg(args, 2, True))
    if word_length < 1:
        raise ValueError("word length must be positive")
    if data_format == "Hex":
        compact = re.sub(r"[^0-9A-Fa-f]", "", to_text(value))
        if len(compact) % 2:
            compact = "0" + compact
        data = bytes.fromhex(compact)
    else:
        data = to_bytes(value)
    if pad and len(data) % word_length:
        data += b"\0" * (-len(data) % word_length)
    output = b"".join(
        data[index : index + word_length][::-1] for index in range(0, len(data), word_length)
    )
    return output.hex() if data_format == "Hex" else output


@implementation("To Lower case", category="Text")
def lower_case(value: Data, _args: Args) -> str:
    return to_text(value).lower()


@implementation("To Upper case", category="Text")
def upper_case(value: Data, args: Args) -> str:
    scope = str(arg(args, 0, "All"))
    text = to_text(value)
    if scope == "Word":
        return text.title()
    if scope == "Sentence":
        return re.sub(
            r"(^|[.!?]\s+)(\w)", lambda match: match.group(1) + match.group(2).upper(), text
        )
    if scope == "Paragraph":
        return re.sub(
            r"(^|\n\s*\n)(\s*\w)", lambda match: match.group(1) + match.group(2).upper(), text
        )
    return text.upper()


@implementation("Swap case", category="Text")
def swap_case(value: Data, _args: Args) -> str:
    return to_text(value).swapcase()


@implementation("Alternating Caps", category="Text")
def alternating_caps(value: Data, _args: Args) -> str:
    return "".join(
        character.upper() if index % 2 == 0 else character.lower()
        for index, character in enumerate(to_text(value))
    )


def _words(value: Data) -> list[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", to_text(value))
    return [part for part in re.split(r"[^\w]+|_+", text, flags=re.UNICODE) if part]


@implementation("To Camel case", category="Text")
def camel_case(value: Data, _args: Args) -> str:
    words = _words(value)
    return "" if not words else words[0].lower() + "".join(word.capitalize() for word in words[1:])


@implementation("To Snake case", category="Text")
def snake_case(value: Data, _args: Args) -> str:
    return "_".join(word.lower() for word in _words(value))


@implementation("To Kebab case", category="Text")
def kebab_case(value: Data, _args: Args) -> str:
    return "-".join(word.lower() for word in _words(value))


@implementation("Normalise Unicode", category="Text")
def normalise_unicode(value: Data, args: Args) -> str:
    form = str(arg(args, 0, "NFC"))
    aliases = {
        "Canonical Composition": "NFC",
        "Canonical Decomposition": "NFD",
        "Compatibility Composition": "NFKC",
        "Compatibility Decomposition": "NFKD",
    }
    normal_form = cast(Literal["NFC", "NFD", "NFKC", "NFKD"], aliases.get(form, form))
    return unicodedata.normalize(normal_form, to_text(value))


@implementation("Remove Diacritics", category="Text")
def remove_diacritics(value: Data, _args: Args) -> str:
    return "".join(
        character
        for character in unicodedata.normalize("NFD", to_text(value))
        if unicodedata.category(character) != "Mn"
    )


@implementation("Remove whitespace", category="Text")
def remove_whitespace(value: Data, args: Args) -> str:
    characters = ""
    for enabled, character in zip(
        (bool(arg(args, index, index < 5)) for index in range(6)),
        " \r\n\t\f.",
        strict=True,
    ):
        if enabled:
            characters += character
    return to_text(value).translate({ord(character): None for character in characters})


@implementation("Add line numbers", category="Text")
def add_line_numbers(value: Data, args: Args) -> str:
    offset = require_int(arg(args, 0, 0))
    lines = to_text(value).split("\n")
    width = len(str(len(lines) + offset))
    return "\n".join(f"{index + offset:>{width}} {line}" for index, line in enumerate(lines, 1))


@implementation("Remove line numbers", category="Text")
def remove_line_numbers(value: Data, _args: Args) -> str:
    return re.sub(r"^[ \t]{0,5}\d+[\s:|\-,.)\]]", "", to_text(value), flags=re.MULTILINE)


@implementation("Head", category="Text")
def head(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    number = require_int(arg(args, 1, 10))
    return delimiter.join(to_text(value).split(delimiter)[:number])


@implementation("Tail", category="Text")
def tail(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    number = require_int(arg(args, 1, 10))
    return delimiter.join(to_text(value).split(delimiter)[-number:])


@implementation("Sort", category="Text")
def sort_items(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    reverse_order = bool(arg(args, 1, False))
    order = str(arg(args, 2, "Alphabetical (case sensitive)"))
    items = to_text(value).split(delimiter)
    if order == "Alphabetical (case insensitive)":
        result = sorted(items, key=str.casefold, reverse=reverse_order)
    elif order == "IP address":
        result = sorted(items, key=_ip_sort_key, reverse=reverse_order)
    elif order == "Numeric":
        result = sorted(items, key=float, reverse=reverse_order)
    elif order == "Numeric (hexadecimal)":
        result = sorted(items, key=_hex_sort_key, reverse=reverse_order)
    elif order == "Length":
        result = sorted(items, key=len, reverse=reverse_order)
    else:
        result = sorted(items, reverse=reverse_order)
    return delimiter.join(result)


def _ip_sort_key(item: str) -> tuple[int, int]:
    address = ipaddress.ip_address(item.strip())
    return address.version, int(address)


def _hex_sort_key(item: str) -> int:
    return int(item, 16)


@implementation("Unique", category="Text")
def unique(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    items = to_text(value).split(delimiter)
    if bool(arg(args, 1, False)):
        counts = Counter(items)
        return delimiter.join(f"{counts[item]} {item}" for item in dict.fromkeys(items))
    return delimiter.join(dict.fromkeys(items))


@implementation("Split", category="Text")
def split(value: Data, args: Args) -> str:
    source = char_rep(arg(args, 0, "Comma"), ",")
    target = char_rep(arg(args, 1, "Line feed"), "\n")
    return target.join(to_text(value).split(source))


@implementation("Filter", category="Text")
def filter_items(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    pattern = re.compile(str(arg(args, 1, "")))
    invert = bool(arg(args, 2, False))
    return delimiter.join(
        item for item in to_text(value).split(delimiter) if bool(pattern.search(item)) != invert
    )


@implementation("Wrap", category="Text")
def wrap(value: Data, args: Args) -> str:
    width = require_int(arg(args, 0, 64), name="line width")
    if width < 1:
        raise ValueError("line width must be positive")
    return "\n".join(
        to_text(value)[index : index + width] for index in range(0, len(to_text(value)), width)
    )


@implementation("Pad lines", category="Text")
def pad_lines(value: Data, args: Args) -> str:
    position = str(arg(args, 0, "Start"))
    length = require_int(arg(args, 1, 5))
    character = _escaped(arg(args, 2, " ")) or " "
    fill = character[0]
    if position == "Start":
        return "\n".join(line.rjust(length, fill) for line in to_text(value).split("\n"))
    return "\n".join(line.ljust(length, fill) for line in to_text(value).split("\n"))


def _toggle_pattern(value: object) -> tuple[str, str]:
    if isinstance(value, dict):
        pattern = str(value.get("string", ""))
        mode = str(value.get("option", "Simple string"))
    else:
        pattern, mode = str(value), "Simple string"
    if mode.startswith("Extended"):
        pattern = _escaped(pattern)
    if mode != "Regex":
        pattern = re.escape(pattern)
    return pattern, mode


@implementation("Find / Replace", category="Text")
def find_replace(value: Data, args: Args) -> str:
    pattern, _ = _toggle_pattern(arg(args, 0, {"string": "", "option": "Simple string"}))
    replacement = _escaped(arg(args, 1, ""))
    replacement = re.sub(r"\$(\d+)", r"\\g<\1>", replacement)
    flags = (
        (re.IGNORECASE if bool(arg(args, 3, False)) else 0)
        | (re.MULTILINE if bool(arg(args, 4, True)) else 0)
        | (re.DOTALL if bool(arg(args, 5, False)) else 0)
    )
    count = 0 if bool(arg(args, 2, True)) else 1
    return re.sub(pattern, replacement, to_text(value), count=count, flags=flags)


@implementation("Count occurrences", category="Text")
def count_occurrences(value: Data, args: Args) -> str:
    pattern, _ = _toggle_pattern(arg(args, 0, {"string": "", "option": "Simple string"}))
    return str(len(re.findall(pattern, to_text(value))))


@implementation("Regular expression", category="Text")
def regular_expression(value: Data, args: Args) -> str:
    pattern = str(arg(args, 1, ""))
    flags = (
        (re.IGNORECASE if bool(arg(args, 2, True)) else 0)
        | (re.MULTILINE if bool(arg(args, 3, True)) else 0)
        | (re.DOTALL if bool(arg(args, 4, False)) else 0)
    )
    display_total = bool(arg(args, 7, False))
    output_format = str(arg(args, 8, "List matches"))
    matches = list(re.finditer(pattern, to_text(value), flags))
    lines: list[str] = []
    for match in matches:
        if output_format in {"List matches", "List matches with capture groups"}:
            lines.append(match.group(0))
        if output_format in {"List capture groups", "List matches with capture groups"}:
            for index, group in enumerate(match.groups(), 1):
                lines.append(
                    f"  Group {index}: {group}"
                    if output_format.startswith("List matches")
                    else str(group)
                )
    output = "\n".join(lines)
    return f"Total found: {len(matches)}\n\n{output}" if display_total else output


@implementation("Strings", category="Extraction")
def strings(value: Data, args: Args) -> str:
    encoding = str(arg(args, 0, "Single byte"))
    minimum = require_int(arg(args, 1, 4), name="minimum length")
    data = to_bytes(value)
    found: list[str] = []
    if encoding in {"Single byte", "All"}:
        found.extend(
            match.decode("latin-1") for match in re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
        )
    if encoding in {"16-bit littleendian", "All"}:
        found.extend(
            match.decode("utf-16le")
            for match in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data)
        )
    if encoding in {"16-bit bigendian", "All"}:
        found.extend(
            match.decode("utf-16be")
            for match in re.findall(rb"(?:\x00[\x20-\x7e]){%d,}" % minimum, data)
        )
    if bool(arg(args, 4, False)):
        found.sort()
    if bool(arg(args, 5, False)):
        found = list(dict.fromkeys(found))
    output = "\n".join(found)
    return f"Total found: {len(found)}\n\n{output}" if bool(arg(args, 3, False)) else output


@implementation("Escape Unicode Characters", category="Text")
def escape_unicode(value: Data, args: Args) -> str:
    prefix = str(arg(args, 0, "\\u"))
    encode_all = bool(arg(args, 1, False))
    padding = require_int(arg(args, 2, 4))
    uppercase = bool(arg(args, 3, True))
    output = ""
    for character in to_text(value):
        if not encode_all and ord(character) < 128:
            output += character
            continue
        hexadecimal = f"{ord(character):0{padding}{'X' if uppercase else 'x'}}"
        output += prefix + hexadecimal
    return output


@implementation("Unescape Unicode Characters", category="Text")
def unescape_unicode(value: Data, args: Args) -> str:
    prefix = str(arg(args, 0, "\\u"))
    pattern = re.escape(prefix) + r"([0-9a-fA-F]{4,8})"
    return re.sub(pattern, lambda match: chr(int(match.group(1), 16)), to_text(value))


@implementation("Escape string", category="Text")
def escape_string(value: Data, args: Args) -> str:
    level = str(arg(args, 0, "Special chars"))
    quote = {"Single": "'", "Double": '"', "Backtick": "`"}.get(str(arg(args, 1, "Single")), "'")
    json_compatible = bool(arg(args, 2, False))
    es6_compatible = bool(arg(args, 3, True))
    uppercase = bool(arg(args, 4, False))
    hexadecimal = "X" if uppercase else "x"
    output: list[str] = []
    specials = {0: r"\0", 8: r"\b", 9: r"\t", 10: r"\n", 12: r"\f", 13: r"\r"}
    for character in to_text(value):
        ordinal = ord(character)
        if character == "\\" or character == quote or (json_compatible and character == '"'):
            output.append("\\" + character)
        elif ordinal in specials:
            output.append(specials[ordinal])
        elif ordinal < 32 or ordinal == 127:
            template = f"\\u{{:04{hexadecimal}}}" if json_compatible else f"\\x{{:02{hexadecimal}}}"
            output.append(template.format(ordinal))
        elif level == "Minimal":
            output.append(character)
        elif level == "Everything" or ordinal > 126:
            if ordinal <= 0xFF and not json_compatible:
                output.append(f"\\x{ordinal:02{hexadecimal}}")
            elif ordinal <= 0xFFFF:
                output.append(f"\\u{ordinal:04{hexadecimal}}")
            elif es6_compatible and not json_compatible:
                output.append(f"\\u{{{ordinal:{hexadecimal}}}}")
            else:
                adjusted = ordinal - 0x10000
                high, low = 0xD800 + (adjusted >> 10), 0xDC00 + (adjusted & 0x3FF)
                output.append(f"\\u{high:04{hexadecimal}}\\u{low:04{hexadecimal}}")
        else:
            output.append(character)
    return "".join(output)


@implementation("Unescape string", category="Text")
def unescape_string(value: Data, _args: Args) -> str:
    return _escaped(to_text(value))


@implementation("Expand alphabet range", category="Text")
def expand_alphabet_range(value: Data, _args: Args) -> str:
    return expand_alphabet(to_text(value))


@implementation("Strip HTTP headers", category="Text")
def strip_http_headers(value: Data, _args: Args) -> str:
    return re.split(r"\r?\n\r?\n", to_text(value), maxsplit=1)[-1]


@implementation("Dechunk HTTP response", category="Text")
def dechunk_http_response(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    output = bytearray()
    position = 0
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0:
            raise ValueError("invalid chunked HTTP body")
        size = int(data[position:line_end].split(b";", 1)[0], 16)
        position = line_end + 2
        if size == 0:
            return bytes(output)
        output.extend(data[position : position + size])
        position += size + 2


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append("\n")


@implementation("Strip HTML tags", category="Text")
@implementation("HTML To Text", category="Text")
def html_to_text(value: Data, args: Args) -> str:
    parser = _TextExtractor()
    parser.feed(to_text(value))
    output = html.unescape("".join(parser.parts))
    if bool(arg(args, 0, True)):
        output = "\n".join(line.strip() for line in output.splitlines())
    if bool(arg(args, 1, True)):
        output = re.sub(r"\n{3,}", "\n\n", output)
    return output.strip()


@implementation("MIME Decoding", category="Text")
def mime_decoding(value: Data, _args: Args) -> str:
    parts: list[str] = []
    for payload, charset in decode_header(to_text(value)):
        parts.append(
            payload.decode(charset or "ascii", "replace") if isinstance(payload, bytes) else payload
        )
    return "".join(parts)


def _sets(value: Data, args: Args) -> tuple[list[list[str]], str]:
    sample_delimiter = _escaped(arg(args, 0, "\\n\\n"))
    item_delimiter = _escaped(arg(args, 1, ","))
    samples = [sample.split(item_delimiter) for sample in to_text(value).split(sample_delimiter)]
    return samples, item_delimiter


@implementation("Set Union", category="Sets")
def set_union(value: Data, args: Args) -> str:
    samples, delimiter = _sets(value, args)
    return delimiter.join(dict.fromkeys(chain.from_iterable(samples)))


@implementation("Set Intersection", category="Sets")
def set_intersection(value: Data, args: Args) -> str:
    samples, delimiter = _sets(value, args)
    if not samples:
        return ""
    intersection = set(samples[0]).intersection(*(set(sample) for sample in samples[1:]))
    return delimiter.join(item for item in samples[0] if item in intersection)


@implementation("Set Difference", category="Sets")
def set_difference(value: Data, args: Args) -> str:
    samples, delimiter = _sets(value, args)
    if not samples:
        return ""
    remainder = set(samples[0]).difference(*(set(sample) for sample in samples[1:]))
    return delimiter.join(item for item in samples[0] if item in remainder)


@implementation("Symmetric Difference", category="Sets")
def symmetric_difference(value: Data, args: Args) -> str:
    samples, delimiter = _sets(value, args)
    counts = Counter(chain.from_iterable(set(sample) for sample in samples))
    return delimiter.join(
        dict.fromkeys(item for sample in samples for item in sample if counts[item] == 1)
    )


@implementation("Power Set", category="Sets")
def power_set(value: Data, args: Args) -> str:
    delimiter = _escaped(arg(args, 0, ","))
    items = to_text(value).split(delimiter)
    return "\n".join(
        delimiter.join(selection)
        for size in range(len(items) + 1)
        for selection in combinations(items, size)
    )


@implementation("Cartesian Product", category="Sets")
def cartesian_product(value: Data, args: Args) -> str:
    samples, delimiter = _sets(value, args)
    return "\n".join(delimiter.join(selection) for selection in product(*samples))
