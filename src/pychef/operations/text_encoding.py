"""Character-set conversion using Python's built-in codec registry."""

from __future__ import annotations

import re

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg

_CODE_PAGES = {
    37: "cp037",
    437: "cp437",
    500: "cp500",
    850: "cp850",
    852: "cp852",
    855: "cp855",
    857: "cp857",
    858: "cp858",
    860: "cp860",
    861: "cp861",
    862: "cp862",
    863: "cp863",
    864: "cp864",
    865: "cp865",
    866: "cp866",
    869: "cp869",
    874: "cp874",
    932: "cp932",
    936: "gbk",
    949: "cp949",
    950: "cp950",
    1200: "utf-16le",
    1201: "utf-16be",
    1250: "cp1250",
    1251: "cp1251",
    1252: "cp1252",
    1253: "cp1253",
    1254: "cp1254",
    1255: "cp1255",
    1256: "cp1256",
    1257: "cp1257",
    1258: "cp1258",
    10000: "mac_roman",
    20127: "ascii",
    28591: "iso8859-1",
    28592: "iso8859-2",
    28593: "iso8859-3",
    28594: "iso8859-4",
    28595: "iso8859-5",
    28596: "iso8859-6",
    28597: "iso8859-7",
    28598: "iso8859-8",
    28599: "iso8859-9",
    28603: "iso8859-13",
    28605: "iso8859-15",
    65000: "utf-7",
    65001: "utf-8",
}


def _codec(label: object) -> str | None:
    text = str(label).strip()
    if not text:
        return None
    match = re.search(r"\((\d+)\)\s*$", text)
    if match:
        code_page = int(match.group(1))
        return _CODE_PAGES.get(code_page, f"cp{code_page}")
    normalized = re.sub(r"[^a-z0-9]", "", text.casefold())
    aliases = {
        "utf8": "utf-8",
        "utf16le": "utf-16le",
        "utf16be": "utf-16be",
        "utf32le": "utf-32le",
        "utf32be": "utf-32be",
        "ascii": "ascii",
        "latin1": "latin-1",
    }
    return aliases.get(normalized, text)


@implementation("Encode text", category="Encodings")
def encode_text(value: Data, args: Args) -> Data:
    codec = _codec(arg(args, 0, "UTF-8 (65001)"))
    if codec is None:
        return "Encoding cannot be empty."
    try:
        return to_text(value).encode(codec)
    except LookupError as exc:
        raise ValueError(f"unsupported encoding: {codec}") from exc


@implementation("Decode text", category="Encodings")
def decode_text(value: Data, args: Args) -> str:
    codec = _codec(arg(args, 0, "UTF-8 (65001)"))
    if codec is None:
        return "Encoding cannot be empty."
    try:
        return to_bytes(value).decode(codec)
    except LookupError as exc:
        raise ValueError(f"unsupported encoding: {codec}") from exc
