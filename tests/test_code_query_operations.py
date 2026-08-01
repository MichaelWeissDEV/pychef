from __future__ import annotations

import json

import pytest

from pychef import bake

DOCUMENT = """{
  "FirstName": "Fred",
  "Surname": "Smith",
  "Age": 28,
  "Address": {"Street": "Hursley Park", "City": "Winchester", "Postcode": "SO21 2JN"},
  "Phone": [
    {"type": "home", "number": "0203 544 1234"},
    {"type": "office", "number": "01962 001234"},
    {"type": "office", "number": "01962 001235"},
    {"type": "mobile", "number": "077 7700 1234"}
  ],
  "Other": {"Over 18 ?": true, "Misc": null}
}"""


def test_jq_official_property_examples() -> None:
    source = '{"data": "testString\\u0000"}'
    assert bake(source, [{"op": "Jq", "args": [".data", True]}]) == "testString\0"
    assert bake(source, [{"op": "Jq", "args": [".data", False]}]) == '"testString\\u0000"'


def test_jq_pipeline_map_and_select() -> None:
    source = '[{"enabled":true,"n":2},{"enabled":false,"n":8},{"enabled":true,"n":4}]'
    assert bake(source, [{"op": "Jq", "args": ["map(select(.enabled) | .n)", False]}]) == "[2,4]"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Surname", '"Smith"'),
        ("Age", "28"),
        ("Address.City", '"Winchester"'),
        ("Other.Misc", "null"),
        ("Other.DoesntExist", '""'),
        ("Other.`Over 18 ?`", "true"),
        ("Phone[-1].number", '"077 7700 1234"'),
        ("Phone.number", '["0203 544 1234","01962 001234","01962 001235","077 7700 1234"]'),
        ("Phone[type='office'].number", '["01962 001234","01962 001235"]'),
        ("Address.*", '["Hursley Park","Winchester","SO21 2JN"]'),
        ("FirstName & ' ' & Surname", '"Fred Smith"'),
        ("5&0&true", '"50true"'),
        ('$base64decode("SGVsbG8gV29ybGQh")', '"Hello World!"'),
        ('$base64encode("Hello World!")', '"SGVsbG8gV29ybGQh"'),
    ],
)
def test_jsonata_official_examples(query: str, expected: str) -> None:
    assert bake(DOCUMENT, [{"op": "Jsonata Query", "args": [query]}]) == expected


def test_javascript_parser_ast_options() -> None:
    result = json.loads(
        bake(
            "// setup\nconst answer = 40 + 2;",
            [{"op": "JavaScript Parser", "args": [True, True, True, True, False]}],
        )
    )
    assert result["type"] == "Program"
    declaration = result["body"][0]
    assert declaration["type"] == "VariableDeclaration"
    assert declaration["declarations"][0]["init"]["type"] == "BinaryExpression"
    assert declaration["range"] == [9, 31]
    assert result["comments"][0]["value"] == " setup"
    assert [token["value"] for token in result["tokens"]][-1] == ";"


def test_javascript_parser_tolerant_mode_reports_error() -> None:
    result = json.loads(
        bake("let = ;", [{"op": "JavaScript Parser", "args": [False, False, False, False, True]}])
    )
    assert result["errors"]
