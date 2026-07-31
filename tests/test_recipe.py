"""Tests for the public recipe API."""

from __future__ import annotations

from typing import cast

import pytest

from pychef import (
    Chef,
    OperationError,
    Recipe,
    RecipeConfig,
    RecipeError,
    RecipeStep,
    UnknownOperationError,
    bake,
)


def test_recipe_bakes_multiple_steps() -> None:
    result = bake(
        "Hello, World!",
        [
            {"op": "To Base64", "args": ["A-Za-z0-9+/="]},
            {"op": "From Base64", "args": ["A-Za-z0-9+/=", True]},
        ],
        return_type="str",
    )
    assert result == "Hello, World!"


def test_recipe_accepts_strings_and_recipe_steps() -> None:
    recipe = Recipe([RecipeStep("To Upper case"), "ROT13"])
    assert Chef().bake("hello", recipe) == "URYYB"


def test_disabled_comment_and_breakpoint_steps() -> None:
    result = Chef().bake_result(
        "hello",
        [
            {"op": "Comment", "args": ["ignored"]},
            {"op": "To Upper case", "disabled": True},
            {"op": "ROT13"},
            {"op": "To Lower case", "breakpoint": True},
        ],
    )
    assert result.result == "uryyb"
    assert result.progress == 3
    assert result.error is None


def test_detailed_result_can_capture_an_error() -> None:
    result = Chef().bake_result(
        "%%%", [{"op": "From Base64", "args": ["A-Za-z0-9+/=", False, True]}], raise_errors=False
    )
    assert result.result == "%%%"
    assert result.type == "string"
    assert isinstance(result.error, OperationError)


@pytest.mark.parametrize(
    "step",
    [42, {}, {"op": 1}, {"op": "ROT13", "args": "bad"}],
)
def test_invalid_recipe_steps_are_rejected(step: object) -> None:
    with pytest.raises(RecipeError):
        Recipe(cast(RecipeConfig, [step]))


def test_unknown_operation_is_explicit() -> None:
    with pytest.raises(UnknownOperationError, match="unknown operation"):
        bake("x", ["Does not exist"])


def test_return_type_conversions() -> None:
    assert bake("hi", [], return_type="bytes") == b"hi"
    assert bake(b"hi", [], return_type="str") == "hi"
