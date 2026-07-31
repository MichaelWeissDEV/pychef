"""Structured format operation tests."""

from __future__ import annotations

import json
import plistlib

from pychef import bake


def test_json_beautify_minify_and_sort() -> None:
    source = '{"z":1,"a":{"x":"✓"}}'
    pretty = bake(source, [{"op": "JSON Beautify", "args": ["  ", True, False]}])
    assert isinstance(pretty, str)
    assert pretty.startswith('{\n  "a"')
    assert bake(pretty, ["JSON Minify"]) == '{"a":{"x":"✓"},"z":1}'


def test_jwt_decode() -> None:
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMiLCJuYW1lIjoiSm9obiJ9."
    assert json.loads(bake(token, ["JWT Decode"])) == {"sub": "123", "name": "John"}


def test_csv_json_round_trips() -> None:
    source = "name,age\r\nAlice,30\r\nBob,40"
    parsed = bake(source, [{"op": "CSV to JSON", "args": [",", "\\r\\n", "Array of dictionaries"]}])
    assert json.loads(parsed) == [{"name": "Alice", "age": "30"}, {"name": "Bob", "age": "40"}]
    assert bake(parsed, [{"op": "JSON to CSV", "args": [",", "\\r\\n"]}]) == source


def test_xml_round_trip_and_comment_removal() -> None:
    source = "<root><!-- comment --><a>1</a><b>2</b></root>"
    pretty = bake(source, [{"op": "XML Beautify", "args": ["  "]}])
    assert isinstance(pretty, str)
    assert "\n  <a>1</a>" in pretty
    minified = bake(pretty, [{"op": "XML Minify", "args": [False]}])
    assert isinstance(minified, str)
    assert "comment" not in minified
    assert "<a>1</a><b>2</b>" in minified


def test_plist_jpath_and_php_serialization() -> None:
    plist = plistlib.dumps({"name": "PyChef", "count": 2})
    assert json.loads(bake(plist, ["P-list Viewer"]))["name"] == "PyChef"
    assert bake('{"a":[{"b":42}]}', [{"op": "JPath expression", "args": ["$.a[0].b"]}]) == "42"
    assert bake('{"a":1,"b":true}', ["PHP Serialize"]) == 'a:2:{s:1:"a";i:1;s:1:"b";b:1;}'


def test_varint_round_trip() -> None:
    encoded = bake("300", ["VarInt Encode"])
    assert encoded == b"\xac\x02"
    assert bake(encoded, ["VarInt Decode"]) == "300"
