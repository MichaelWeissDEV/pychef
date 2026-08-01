"""Text and byte sequence operation tests."""

from __future__ import annotations

import pytest

from pychef import bake


def test_reverse_modes_and_byte_slicing() -> None:
    assert bake("abc", [{"op": "Reverse", "args": ["Character"]}], return_type="str") == "cba"
    assert bake(b"abc", [{"op": "Reverse", "args": ["Byte"]}]) == b"cba"
    assert bake("a\nb", [{"op": "Reverse", "args": ["Line"]}], return_type="str") == "b\na"
    assert bake("0123456789", [{"op": "Take bytes", "args": [2, 4, False]}]) == b"2345"
    assert bake("0123456789", [{"op": "Drop bytes", "args": [2, 4, False]}]) == b"016789"


@pytest.mark.parametrize(
    ("operation", "args", "source", "expected"),
    [
        ("Take nth bytes", [4, 0, False], "0123456789", b"048"),
        ("Take nth bytes", [4, 0, True], "01234\n56789", b"04\n59"),
        ("Drop nth bytes", [4, 0, False], "0123456789", b"1235679"),
        ("Drop nth bytes", [4, 5, True], "012345\n6789ab", b"01234\n6789a"),
    ],
)
def test_official_nth_byte_vectors(
    operation: str, args: list[object], source: str, expected: bytes
) -> None:
    assert bake(source, [{"op": operation, "args": args}]) == expected


def test_cleanup_and_endianness() -> None:
    assert bake(b"a\0b\0", ["Remove null bytes"]) == b"ab"
    assert (
        bake(
            "a b\r\nc.\t",
            [{"op": "Remove whitespace", "args": [True, True, True, True, True, True]}],
        )
        == "abc"
    )
    assert bake("00112233", [{"op": "Swap endianness", "args": ["Hex", 2, True]}]) == "11003322"


def test_case_and_unicode_operations() -> None:
    assert bake("hello WORLD", ["To Lower case"]) == "hello world"
    assert bake("hello world", [{"op": "To Upper case", "args": ["Word"]}]) == "Hello World"
    assert bake("AbC", ["Swap case"]) == "aBc"
    assert bake("abcdef", ["Alternating Caps"]) == "AbCdEf"
    assert bake("hello-world_test", ["To Camel case"]) == "helloWorldTest"
    assert bake("HelloWorld", ["To Snake case"]) == "hello_world"
    assert bake("HelloWorld", ["To Kebab case"]) == "hello-world"
    assert bake("e\u0301", [{"op": "Normalise Unicode", "args": ["NFC"]}]) == "é"
    assert bake("Crème brûlée", ["Remove Diacritics"]) == "Creme brulee"


def test_lines_sort_unique_split_filter_wrap_and_padding() -> None:
    numbered = bake("a\nb", [{"op": "Add line numbers", "args": [0]}])
    assert bake(numbered, ["Remove line numbers"]) == "a\nb"
    assert bake("3\n1\n2", [{"op": "Sort", "args": ["Line feed", False, "Numeric"]}]) == "1\n2\n3"
    assert bake("b\na\nb", [{"op": "Unique", "args": ["Line feed", True]}]) == "2 b\n1 a"
    assert bake("a,b,c", [{"op": "Split", "args": ["Comma", "Line feed"]}]) == "a\nb\nc"
    assert (
        bake("cat\ndog\ncar", [{"op": "Filter", "args": ["Line feed", "^ca", False]}]) == "cat\ncar"
    )
    assert bake("abcdefgh", [{"op": "Wrap", "args": [3]}]) == "abc\ndef\ngh"
    assert bake("a\nbb", [{"op": "Pad lines", "args": ["Start", 3, "0"]}]) == "00a\n0bb"
    assert bake("1\n2\n3", [{"op": "Head", "args": ["Line feed", 2]}]) == "1\n2"
    assert bake("1\n2\n3", [{"op": "Tail", "args": ["Line feed", 2]}]) == "2\n3"


def test_find_regex_strings_and_escaping() -> None:
    replaced = bake(
        "Foo foo",
        [
            {
                "op": "Find / Replace",
                "args": [{"string": "foo", "option": "Simple string"}, "bar", True, True],
            }
        ],
    )
    assert replaced == "bar bar"
    assert (
        bake(
            "abab",
            [{"op": "Count occurrences", "args": [{"string": "ab", "option": "Simple string"}]}],
        )
        == "2"
    )
    matches = bake(
        "a1 b22",
        [
            {
                "op": "Regular expression",
                "args": ["", r"\d+", False, True, False, False, False, True, "List matches"],
            }
        ],
    )
    assert matches == "Total found: 2\n\n1\n22"
    assert (
        bake(b"\0hello\0xx\0world!\0", [{"op": "Strings", "args": ["Single byte", 4]}])
        == "hello\nworld!"
    )
    escaped = bake("✓", [{"op": "Escape Unicode Characters", "args": ["\\u", False, 4, True]}])
    assert escaped == "\\u2713"
    assert bake(escaped, [{"op": "Unescape Unicode Characters", "args": ["\\u"]}]) == "✓"
    assert bake(r"line\nnext", ["Unescape string"]) == "line\nnext"
    assert bake("a-c0-2", ["Expand alphabet range"]) == "abc012"


def test_escape_and_unescape_string_official_vectors() -> None:
    recipe = [{"op": "Escape string", "args": ["Special chars", "Single", False, True, False]}]
    assert bake("Escape 'these' quotes.", recipe) == "Escape \\'these\\' quotes."
    plain = "null\0backspace\btab\tnewline\nverticaltab\vformfeed\fcarriagereturn\r©♥𝌆"
    escaped = bake(plain, recipe)
    assert escaped == (
        r"null\0backspace\btab\tnewline\nverticaltab\x0bformfeed\fcarriagereturn\r"
        r"\xa9\u2665\u{1d306}"
    )
    assert bake(escaped, ["Unescape string"]) == plain
    assert bake(r"\0\01\012\1\12", ["Unescape string"]) == "\0\1\n\1\n"
    assert bake(r"\u0061\u{0062}", ["Unescape string"]) == "ab"


def test_html_mime_http_and_sets() -> None:
    assert bake("<p>Hello <b>world</b></p>", ["HTML To Text"]) == "Hello world"
    assert bake("HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody", ["Strip HTTP headers"]) == "body"
    assert bake(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", ["Dechunk HTTP response"]) == b"Wikipedia"
    assert bake("=?utf-8?b?R3LDvMOfZQ==?=", ["MIME Decoding"]) == "Grüße"
    assert bake("a,b\n\nb,c", ["Set Union"]) == "a,b,c"
    assert bake("a,b\n\nb,c", ["Set Intersection"]) == "b"
    assert bake("a,b\n\nb,c", ["Set Difference"]) == "a"
    assert bake("a,b\n\nb,c", ["Symmetric Difference"]) == "a,c"
    assert bake("a,b", ["Power Set"]).splitlines() == ["", "a", "b", "a,b"]
    assert bake("a,b\n\n1,2", ["Cartesian Product"]) == "a,1\na,2\nb,1\nb,2"
