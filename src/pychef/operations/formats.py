"""Structured-data and markup format operations."""

from __future__ import annotations

import base64
import csv
import io
import json
import plistlib
import re
from typing import Any
from xml.dom import minidom

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg


def _escaped(value: object) -> str:
    return str(value).replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t")


def _json(value: Data) -> Any:
    return json.loads(to_text(value))


@implementation("JSON Beautify", category="Serialisation")
def json_beautify(value: Data, args: Args) -> str:
    if not value:
        return ""
    indent = _escaped(arg(args, 0, "    "))
    sort_keys = bool(arg(args, 1, False))
    parsed = _json(value)
    if indent == "\t":
        return json.dumps(parsed, ensure_ascii=False, indent="\t", sort_keys=sort_keys)
    if indent and set(indent) == {" "}:
        return json.dumps(parsed, ensure_ascii=False, indent=len(indent), sort_keys=sort_keys)
    lines = json.dumps(parsed, ensure_ascii=False, indent=1, sort_keys=sort_keys).splitlines()
    return "\n".join(line.replace(" ", indent, len(line) - len(line.lstrip())) for line in lines)


@implementation("JSON Minify", category="Serialisation")
def json_minify(value: Data, _args: Args) -> str:
    if not value:
        return ""
    return json.dumps(_json(value), ensure_ascii=False, separators=(",", ":"))


@implementation("JWT Decode", category="Serialisation")
def jwt_decode(value: Data, _args: Args) -> str:
    parts = to_text(value).split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain three dot-separated parts")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    parsed = json.loads(base64.urlsafe_b64decode(payload))
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))


@implementation("CSV to JSON", category="Serialisation")
def csv_to_json(value: Data, args: Args) -> str:
    cell_delimiters = _escaped(arg(args, 0, ","))
    row_delimiters = _escaped(arg(args, 1, "\\r\\n"))
    output_format = str(arg(args, 2, "Array of dictionaries"))
    delimiter = cell_delimiters[0] if cell_delimiters else ","
    text = to_text(value)
    if row_delimiters not in {"\r\n", "\n"}:
        text = text.replace(row_delimiters, "\n")
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    if output_format == "Array of dictionaries" and rows:
        header = rows[0]
        parsed: Any = [dict(zip(header, row, strict=False)) for row in rows[1:]]
    else:
        parsed = rows
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))


@implementation("JSON to CSV", category="Serialisation")
def json_to_csv(value: Data, args: Args) -> str:
    cell_delimiter = _escaped(arg(args, 0, ","))
    row_delimiter = _escaped(arg(args, 1, "\\r\\n"))
    parsed = _json(value)
    rows = parsed if isinstance(parsed, list) else [parsed]
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=cell_delimiter[0], lineterminator=row_delimiter)
    if rows and all(isinstance(row, dict) for row in rows):
        headers = list(dict.fromkeys(key for row in rows for key in row))
        writer.writerow(headers)
        writer.writerows([row.get(header, "") for header in headers] for row in rows)
    else:
        for row in rows:
            writer.writerow(row if isinstance(row, list) else [row])
    return output.getvalue().removesuffix(row_delimiter)


@implementation("XML Beautify", category="Serialisation")
def xml_beautify(value: Data, args: Args) -> str:
    indent = _escaped(arg(args, 0, "\\t"))
    document = minidom.parseString(to_bytes(value))
    return document.toprettyxml(indent=indent).strip()


@implementation("XML Minify", category="Serialisation")
def xml_minify(value: Data, args: Args) -> str:
    preserve_comments = bool(arg(args, 0, False))
    document = minidom.parseString(to_bytes(value))
    if not preserve_comments:
        for node in list(document.childNodes):
            _remove_comments(node)
    return re.sub(r">\s+<", "><", document.toxml())


def _remove_comments(node: Any) -> None:
    for child in list(node.childNodes):
        if child.nodeType == child.COMMENT_NODE:
            node.removeChild(child)
        else:
            _remove_comments(child)


@implementation("P-list Viewer", category="Serialisation")
def plist_viewer(value: Data, _args: Args) -> str:
    parsed = plistlib.loads(to_bytes(value))
    return json.dumps(parsed, ensure_ascii=False, indent=4, default=str)


@implementation("JPath expression", category="Serialisation")
def jpath(value: Data, args: Args) -> str:
    expression = str(arg(args, 0, ""))
    current = _json(value)
    tokens = re.findall(r"(?:^|\.)([^.\[\]]+)|\[(\d+)\]", expression.lstrip("$"))
    for key, index in tokens:
        current = current[int(index)] if index else current[key]
    return (
        json.dumps(current, ensure_ascii=False, separators=(",", ":"))
        if isinstance(current, (dict, list))
        else str(current)
    )


@implementation("PHP Serialize", category="Serialisation")
def php_serialize(value: Data, _args: Args) -> str:
    return _php_encode(_json(value))


def _php_encode(value: Any) -> str:
    if value is None:
        return "N;"
    if isinstance(value, bool):
        return f"b:{int(value)};"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, float):
        return f"d:{value};"
    if isinstance(value, str):
        return f's:{len(value.encode())}:"{value}";'
    if isinstance(value, list):
        body = "".join(_php_encode(index) + _php_encode(item) for index, item in enumerate(value))
        return f"a:{len(value)}:{{{body}}}"
    if isinstance(value, dict):
        body = "".join(_php_encode(key) + _php_encode(item) for key, item in value.items())
        return f"a:{len(value)}:{{{body}}}"
    raise ValueError(f"cannot PHP-serialize {type(value).__name__}")


@implementation("VarInt Encode", category="Serialisation")
def varint_encode(value: Data, _args: Args) -> bytes:
    number = int(to_text(value).strip(), 0)
    if number < 0:
        number = (number << 1) ^ (number >> number.bit_length())
    output = bytearray()
    while number > 0x7F:
        output.append((number & 0x7F) | 0x80)
        number >>= 7
    output.append(number)
    return bytes(output)


@implementation("VarInt Decode", category="Serialisation")
def varint_decode(value: Data, _args: Args) -> str:
    result = shift = 0
    for byte in to_bytes(value):
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return str(result)
        shift += 7
        if shift > 70:
            raise ValueError("VarInt is too large")
    raise ValueError("truncated VarInt")
