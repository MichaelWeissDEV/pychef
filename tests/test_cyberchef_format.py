"""Import and export of CyberChef's own recipe formats (Chef format, JSON, links)."""

from __future__ import annotations

import pytest

from pychef import Pipeline, Recipe, RecipeError, UnknownOperationError, bake

# Strings as the CyberChef web app produces them ("Save recipe" -> Chef format).
CHEF = "From_Hex('Auto')To_Base64('A-Za-z0-9+/=')"
LINK = (
    "https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')"
    "To_Base64('A-Za-z0-9%2B/%3D')&input=NDE0MjQz"
)


def test_chef_format_round_trip_and_execution() -> None:
    recipe = Recipe.from_cyberchef(CHEF)
    assert recipe.to_config() == [
        {"op": "From Hex", "args": ["Auto"]},
        {"op": "To Base64", "args": ["A-Za-z0-9+/="]},
    ]
    assert recipe.to_cyberchef() == CHEF
    assert recipe.to_cyberchef(newline=True) == "From_Hex('Auto')\nTo_Base64('A-Za-z0-9+/=')\n"
    assert bake("414243", recipe) == "QUJD"
    assert Pipeline(recipe.steps)("414243") == "QUJD"


def test_multiline_json_and_empty_inputs() -> None:
    assert Recipe.from_cyberchef("From_Hex('Auto')\r\nTo_Base64('A-Za-z0-9+/=')\n").steps == (
        Recipe.from_cyberchef(CHEF).steps
    )
    json_text = '[{"op":"From Hex","args":["Auto"]},{"op":"To Base64","args":["A-Za-z0-9+/="]}]'
    assert Recipe.from_cyberchef(json_text).steps == Recipe.from_cyberchef(CHEF).steps
    assert len(Recipe.from_cyberchef("   ")) == 0


@pytest.mark.parametrize(
    "args",
    [
        [{"option": "Regex", "string": 'it\'s "quoted" \\d+ \\\\ ü\n'}, "x", True, False],
        [0, -1.5, None, [], {}, ["nested", {"k": "v'"}]],
        ["", "'", '"', "\\", "/", ")", "(", ","],
    ],
)
def test_arguments_with_quotes_escapes_and_nesting_round_trip(args: list[object]) -> None:
    recipe = Recipe([{"op": "Find / Replace", "args": args}])
    text = recipe.to_cyberchef()
    assert Recipe.from_cyberchef(text).to_config() == recipe.to_config()


def test_disabled_and_breakpoint_flags() -> None:
    recipe = Recipe(
        [
            {"op": "To Hex", "args": ["Space", 0], "disabled": True},
            {"op": "To Base64", "args": ["A-Za-z0-9+/="], "breakpoint": True},
        ]
    )
    text = recipe.to_cyberchef()
    assert text == "To_Hex('Space',0/disabled)To_Base64('A-Za-z0-9+/='/breakpoint)"
    assert Recipe.from_cyberchef(text).steps == recipe.steps


def test_upstream_escaping_of_backslashes_is_preserved() -> None:
    # CyberChef writes the regex \d+ as '\\d+' (JSON escaping inside single quotes).
    recipe = Recipe.from_cyberchef("Regular_expression('User defined','\\\\d+',true)")
    assert recipe.steps[0].op == "Regular expression"
    assert recipe.steps[0].args == ("User defined", "\\d+", True)


def test_links_carry_recipe_and_input() -> None:
    recipe, data = Recipe.from_cyberchef_link(LINK)
    assert data == b"414243"  # the input parameter is unpadded Base64 of the input bytes
    assert bake(data, recipe) == "QUJD"
    assert recipe.to_cyberchef() == CHEF
    assert recipe.to_cyberchef_link(b"414243") == LINK
    assert recipe.to_cyberchef_link("414243") == LINK
    assert Recipe.from_cyberchef(LINK).steps == recipe.steps
    assert Recipe.from_cyberchef_link(recipe.to_cyberchef_link())[1] is None
    own = recipe.to_cyberchef_link(base_url="https://chef.example.test/")
    assert own.startswith("https://chef.example.test/#recipe=")


def test_binary_input_survives_links() -> None:
    data = bytes(range(256))
    _, restored = Recipe.from_cyberchef_link(Recipe(["To Hex"]).to_cyberchef_link(data))
    assert restored == data


@pytest.mark.parametrize(
    "text",
    [
        "From_Hex('Auto'",
        "From_Hex('Auto)",
        "('Auto')",
        "From_Hex(bogus)",
        "[1, 2",
        '{"op": "From Hex"}',
        "https://gchq.github.io/CyberChef/#input=QUJD",
    ],
)
def test_malformed_text_raises_recipe_error(text: str) -> None:
    with pytest.raises(RecipeError):
        Recipe.from_cyberchef(text)


def test_non_json_arguments_cannot_be_exported() -> None:
    with pytest.raises(TypeError, match="not JSON serializable"):
        Recipe([{"op": "XOR", "args": [b"\x01"]}]).to_cyberchef()


def test_plain_string_recipe_is_rejected_with_guidance() -> None:
    """Regression: a str used to be iterated per character ('unknown operation: F')."""
    with pytest.raises(RecipeError, match=r"\['From Hex'\]"):
        bake("41", "From Hex")  # str is a Sequence, so type checkers accept it
    with pytest.raises(RecipeError, match="from_cyberchef"):
        Recipe(CHEF)


@pytest.mark.parametrize(
    ("name", "suggestion"),
    [("To base64", "To Base64"), ("to_base64", "To Base64"), ("From hex", "From Hex")],
)
def test_unknown_operation_suggests_close_names(name: str, suggestion: str) -> None:
    with pytest.raises(UnknownOperationError, match=f"did you mean '{suggestion}'"):
        bake("41", [name])


def test_unknown_operation_without_close_match_has_no_suggestion() -> None:
    with pytest.raises(UnknownOperationError) as excinfo:
        bake("41", ["Completely Unrelated Thing"])
    assert "did you mean" not in str(excinfo.value)
