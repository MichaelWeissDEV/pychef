"""Compatibility regressions for generation, analysis, and template operations."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

from pychef import registry
from pychef.operations import misc


def run(name: str, value: str | bytes = "", args: Sequence[Any] | None = None) -> Any:
    return registry.get(name).run(value, args or [])


def test_de_bruijn_official_vector_and_limits() -> None:
    assert run("Generate De Bruijn Sequence", "ignored", [2, 3]) == "00010111"
    sequence = run("Generate De Bruijn Sequence", "", [4, 5])
    assert len(sequence) == 4**5
    assert (
        len({(sequence + sequence[:4])[index : index + 5] for index in range(len(sequence))})
        == 4**5
    )
    for args in ([1, 3], [10, 3], [2, 1], [9, 6]):
        with pytest.raises(ValueError):
            run("Generate De Bruijn Sequence", "", args)


@pytest.mark.parametrize(
    "args",
    [[0, "Words"], [100_001, "Words"], [1_000_001, "Bytes"], [1, "Novels"]],
)
def test_lorem_ipsum_rejects_invalid_or_excessive_requests(args: list[object]) -> None:
    with pytest.raises(ValueError):
        run("Generate Lorem Ipsum", "", args)


def test_frequency_distribution_matches_official_json_shape() -> None:
    result = json.loads(run("Frequency distribution", b"aba", [False, False]))
    assert result["dataLength"] == 3
    assert result["distribution"][ord("a")] == 2
    assert result["distribution"][ord("b")] == 1
    assert result["percentages"][ord("a")] == pytest.approx(200 / 3)
    assert result["bytesRepresented"] == 2
    assert len(result["distribution"]) == len(result["percentages"]) == 256
    with pytest.raises(ValueError, match="No data"):
        run("Frequency distribution")


def test_fuzzy_match_highlights_subsequence_and_escapes_html() -> None:
    assert run("Fuzzy Match", "Don't Panic", ["dpan"]) == (
        '<span class="hl1"><b>D</b>on&#x27;t <b>Pan</b></span>ic'
    )
    assert run("Fuzzy Match", "<script>", ["zzz"]) == "&lt;script&gt;"
    repeated = run("Fuzzy Match", "abc--abc", ["ac"])
    assert 'class="hl1"' in repeated and 'class="hl2"' in repeated


@pytest.mark.parametrize(
    ("plain", "mode", "expected"),
    [
        ("“Hello,” she said, \u2018yes.\u2019", "Include", "\"Hello,\" she said, 'yes.'"),
        ("page 1\u20133 — wait…", "Include", "page 1-3 -- wait..."),
        ("Foo© Bar® Baz™", "Include", "Foo(c) Bar(r) Baz(tm)"),
        ("← → ↔ ⇒ « »", "Include", "<-- --> <-> ==> << >>"),
        ("3 \u00d7 4 ÷ 2 = 6, ±0.5 • item", "Include", "3 x 4 / 2 = 6, +/-0.5 * item"),
        ("warning: ☣ hazard", "Include", "warning: ☣ hazard"),
        ("warning: ☣ hazard", "Remove", "warning:  hazard"),
        ("warning: ☣ hazard", "Replace with '.'", "warning: . hazard"),
    ],
)
def test_escape_smart_characters_official_vectors(plain: str, mode: str, expected: str) -> None:
    assert run("Escape Smart Characters", plain, [mode]) == expected


def test_random_generator_output_formats_are_cyberchef_compatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(misc.secrets, "token_bytes", lambda count: bytes(range(1, count + 1)))
    assert run("Pseudo-Random Number Generator", "", [3, "Hex"]) == "010203"
    assert run("Pseudo-Random Number Generator", "", [3, "Integer"]) == str(0x030201)
    assert run("Pseudo-Random Number Generator", "", [3, "Byte array"]) == "[1,2,3]"
    assert run("Pseudo-Random Number Generator", "", [3, "Raw"]) == b"\x01\x02\x03"

    monkeypatch.setattr(misc.secrets, "randbelow", lambda _range: 1)
    assert run("Pseudo-Random Integer Generator", "", [2, 10, 20, "Comma", "Decimal"]) == ("11,11")
    monkeypatch.setattr(misc.secrets, "randbelow", lambda _range: 0)
    assert run("Pseudo-Random Integer Generator", "", [1, 65, 65, "Space", "Raw"]) == "A"


def test_offset_checker_highlights_matching_positions_and_escapes_html() -> None:
    result = run("Offset checker", "abc<\n\naxc>\n\nabc&", ["\\n\\n"])
    assert result == (
        "<span class='hl5'>a</span>b<span class='hl5'>c</span>&lt;\n\n"
        "<span class='hl5'>a</span>x<span class='hl5'>c</span>&gt;\n\n"
        "<span class='hl5'>a</span>b<span class='hl5'>c</span>&amp;"
    )
    with pytest.raises(ValueError, match="not enough"):
        run("Offset checker", "one sample", ["|"])


def test_sql_beautify_official_basic_vector_and_minify() -> None:
    source = "SELECT MONTH, ID, RAIN_I, TEMP_F FROM STATS;"
    expected = "SELECT\n  MONTH,\n  ID,\n  RAIN_I,\n  TEMP_F\nFROM\n  STATS;"
    assert run("SQL Beautify", source, ["  "]) == expected
    assert run("SQL Minify", expected) == source


def test_sql_beautify_official_nested_upsert_vector() -> None:
    source = (
        "INSERT INTO Table1 SELECT * FROM (SELECT :Bind1 as Field1, :Bind2 as Field2, "
        ":id as id) as new_data ON DUPLICATE KEY UPDATE Field1 = new_data.Field1, "
        "Field2 = new_data.Field2;"
    )
    expected = (
        "INSERT INTO\n  Table1\nSELECT\n  *\nFROM\n  (\n    SELECT\n      :Bind1 as Field1,\n"
        "      :Bind2 as Field2,\n      :id as id\n  ) as new_data\nON DUPLICATE KEY UPDATE\n"
        "  Field1 = new_data.Field1,\n  Field2 = new_data.Field2;"
    )
    assert run("SQL Beautify", source, ["  "]) == expected


def test_derive_evp_key_known_openssl_vectors_and_ignores_input() -> None:
    password = {"string": "password", "option": "UTF8"}
    salt = {"string": "3132333435363738", "option": "Hex"}
    args = [password, 256, 1, "MD5", salt]
    expected = "bbb0ddff1b944b3cc68eaaeb7ac20099e5155bae6ed28f668b60cbc4157de1bd"
    assert run("Derive EVP key", "ignored", args) == expected
    assert run("Derive EVP key", "different input", args) == expected
    assert (
        run(
            "Derive EVP key",
            "also ignored",
            [password, 128, 1, "MD5", {"string": "", "option": "Hex"}],
        )
        == "5f4dcc3b5aa765d61d8327deb882cf99"
    )


def test_extract_dates_and_file_paths_follow_upstream_patterns_and_options() -> None:
    dates = "valid 2026-08-01 01/08/2026 08.01.2026 invalid 26-8-1 1899-01-01"
    assert run("Extract dates", dates) == "2026-08-01\n01/08/2026\n08.01.2026"
    assert run("Extract dates", dates, [True]).startswith("Total found: 3\n\n")

    paths = r"C:\Users\Alice\flag.txt /var/log/auth.log C:\Users\Alice\flag.txt /tmp/a"
    extracted = run("Extract file paths", paths, [True, True, True, True, True])
    assert extracted == "Total found: 3\n\n/tmp/a\n/var/log/auth.log\nC:\\Users\\Alice\\flag.txt"
    assert run("Extract file paths", paths, [False, False]) == ""


def test_code_minifiers_do_not_corrupt_strings_or_comment_like_content() -> None:
    javascript = 'const url = "https://example.test/a//b"; // remove me\nconst value = "{ x; }";'
    minified = run("JavaScript Minify", javascript)
    assert minified == 'const url="https://example.test/a//b";const value="{ x; }";'
    beautified = run("JavaScript Beautify", minified, ["  "])
    assert '"https://example.test/a//b"' in beautified
    assert '"{ x; }"' in beautified
    css = 'a::before { content: "/* not a comment */"; color: red; } /* remove */'
    assert run("CSS Minify", css, [False]) == 'a::before{content:"/* not a comment */";color:red;}'


def test_substitute_official_vectors_ranges_and_case_handling() -> None:
    plain = "flee at once. we are discovered!"
    source = "abcdefghijklmnopqrstuvwxyz"
    target = "zebrascdfghijklmnopqtuvwxy"
    assert run("Substitute", plain, [source, target]) == "siaa zq lkba. va zoa rfpbluaoar!"
    assert run("Substitute", plain, [source, target[:-1]]).startswith(
        "Warning: Plaintext and Ciphertext lengths differ\n\n"
    )
    assert run("Substitute", "AbC 012", ["a-c0-2", "x-z7-9", True]) == "XyZ 789"


@pytest.mark.parametrize(
    ("input_json", "definition", "expected"),
    [
        ("{}", "Hello, world!", "Hello, world!"),
        ('{"one": 1, "two": 2}', "{{ one }} {{ two }}", "1 2"),
        (
            '{"users":[{"name":"Someone","age":25},{"name":"Someone Else","age":32}]}',
            '{{#*inline "user"}}\nName: {{ name }}\nAge: {{ age }}\n{{/inline}}\n'
            "{{#each users}}\n{{> user}}\n\n{{/each}}",
            "Name: Someone\nAge: 25\n\nName: Someone Else\nAge: 32\n\n",
        ),
        (
            '{"test":"<script></script>"}',
            "<script></script>{{ test }}",
            "<script></script>&lt;script&gt;&lt;/script&gt;",
        ),
    ],
)
def test_template_official_vectors(input_json: str, definition: str, expected: str) -> None:
    assert run("Template", input_json, [definition]) == expected


def test_template_raw_nested_and_invalid_json() -> None:
    definition = "{{#if show}}{{{raw}}}:{{#each values}}{{@index}}={{this}};{{/each}}{{/if}}"
    assert run("Template", '{"show":true,"raw":"<b>","values":["x","y"]}', [definition]) == (
        "<b>:0=x;1=y;"
    )
    with pytest.raises(ValueError, match="invalid JSON"):
        run("Template", "not-json", ["{{this}}"])
