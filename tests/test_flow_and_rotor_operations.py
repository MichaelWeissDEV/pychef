"""Tests for recipe flow control, Magic, and historical rotor machines."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

from pychef import Chef, Recipe, registry


def run(name: str, value: str | bytes, args: Sequence[Any] | None = None) -> Any:
    return registry.get(name).run(value, args or [])


def test_flow_marker_operations_are_direct_identities() -> None:
    for name in ("Conditional Jump", "Fork", "Jump", "Merge", "Register", "Subsection"):
        assert run(name, b"data", ["ignored"]) == b"data"


def test_automated_validation_success_and_failures() -> None:
    assert (
        run(
            "Automated Validation Test Op",
            "",
            [5, 1.5, "hello", "", {"option": "Option A", "string": "test"}, "Option 1", "Option 2"],
        )
        == "Success"
    )
    invalid: list[list[Any]] = [
        [4, 1.5, "hello"],
        [5, 1.4, "hello"],
        [5, 1.5, "toolong"],
        [5, 1.5, "ok", "", {}],
        [5, 1.5, "ok", "", {"string": "ok"}, "bad"],
        [5, 1.5, "ok", "", {"string": "ok"}, "Option 1", "bad"],
    ]
    for args in invalid:
        with pytest.raises(ValueError):
            run("Automated Validation Test Op", "", args)


def test_magic_hex_base64_png_and_crib() -> None:
    assert json.loads(run("Magic", "68656c6c6f"))[0]["recipe"][0]["op"] == "From Hex"
    suggestions = json.loads(run("Magic", "aGVsbG8="))
    assert any(item["recipe"][0]["op"] == "From Base64" for item in suggestions)
    png = run("Generate Image", b"abc", ["RGB", 1, 1])
    assert json.loads(run("Magic", png))[0]["data"] == "PNG image"
    assert json.loads(run("Magic", "68656c6c6f", [3, 3, False, "absent"])) == []


def test_register_replaces_future_nested_arguments() -> None:
    recipe = Recipe(
        [
            {"op": "Register", "args": [r"id=(\d+)", True, False, False]},
            {
                "op": "Find / Replace",
                "args": [{"string": "id=42", "option": "Simple string"}, "$R0", True],
            },
        ]
    )
    assert recipe.execute("id=42")[0] == "42"


def test_jump_forward_backward_and_conditional() -> None:
    forward = [
        {"op": "Jump", "args": ["end", 10]},
        "Reverse",
        {"op": "Label", "args": ["end"]},
        "To Upper case",
    ]
    assert Chef().bake("abc", forward) == "ABC"
    backward = [
        {"op": "Label", "args": ["start"]},
        "ROT13",
        {"op": "Jump", "args": ["start", 1]},
    ]
    assert Chef().bake("hello", backward) == "hello"
    conditional: list[Any] = [
        {"op": "Conditional Jump", "args": ["hello", False, "end", 10]},
        "Reverse",
        {"op": "Label", "args": ["end"]},
    ]
    assert Chef().bake("hello", conditional) == "hello"
    conditional[0]["args"] = ["hello", True, "end", 10]
    assert Chef().bake("hello", conditional) == b"olleh"


def test_fork_subsection_nested_and_ignore_errors() -> None:
    fork = [
        {"op": "Fork", "args": [",", "|", False]},
        "Reverse",
        {"op": "Merge", "args": []},
    ]
    assert Chef().bake("abc,def", fork) == "cba|fed"
    subsection: list[Any] = [
        {"op": "Subsection", "args": [r"\d+", True, True, False]},
        "Reverse",
        {"op": "Merge", "args": []},
    ]
    assert Chef().bake("a12b345", subsection) == "a21b543"
    subsection[0]["args"] = [r"\d+", True, False, False]
    assert Chef().bake("a12b345", subsection) == "a21b345"
    ignore = [
        {"op": "Fork", "args": [",", ",", True]},
        "From Decimal",
        {"op": "Merge", "args": []},
    ]
    assert Chef().bake("97,invalid", ignore) == "a,invalid"


def test_enigma_known_vector_symmetry_and_options() -> None:
    assert run("Enigma", "AAAAA") == "BDZGO"
    encrypted = run("Enigma", "HELLO WORLD")
    assert run("Enigma", encrypted) == "HELLO WORLD"
    args: list[object] = [
        "3-rotor",
        "Beta",
        "A",
        "A",
        "V",
        "B",
        "M",
        "IV",
        "C",
        "N",
        "III",
        "D",
        "O",
        "C",
        "AB CD EF",
        False,
    ]
    encrypted = run("Enigma", "Test 123", args)
    assert run("Enigma", encrypted, args) == "TEST 123"


def test_bombe_impossible_menu_and_multiple_bombe() -> None:
    result = json.loads(run("Bombe", "AAAA", ["3-rotor", "Beta", "I", "II", "III", "B", "AAAA", 0]))
    assert result == {"nLoops": 0, "result": []}
    multiple = json.loads(
        run(
            "Multiple Bombe",
            "AAAA",
            ["User defined", "I\nII\nIII", "", "B", "AAAA", 0, True],
        )
    )
    assert multiple == []
    with pytest.raises(ValueError):
        run("Bombe", "ABC", ["3-rotor", "Beta", "I", "II", "III", "B", "", 0])


@pytest.mark.parametrize("name", ["Typex", "SIGABA"])
def test_generic_rotor_machines_are_symmetric(name: str) -> None:
    encrypted = run(name, "HELLO WORLD")
    assert encrypted != "HELLO WORLD"
    assert run(name, encrypted) == "HELLO WORLD"


def test_lorenz_plaintext_and_ita2_round_trips() -> None:
    encrypted = run("Lorenz", "HELLO")
    assert run("Lorenz", encrypted) == "HELLO"
    send_args: list[object] = ["SZ40", "BREAM Pattern", False, "Send", "Plaintext", "ITA2"]
    receive_args: list[object] = ["SZ40", "BREAM Pattern", False, "Receive", "ITA2", "Plaintext"]
    ita2 = run("Lorenz", "TEST", send_args)
    assert reformat_codes(ita2)
    assert run("Lorenz", ita2, receive_args) == "TEST"


def reformat_codes(value: str | bytes) -> bool:
    return all(len(code) == 5 and set(code) <= {"0", "1"} for code in str(value).split())


def test_colossus_statistics() -> None:
    result = json.loads(run("Colossus", "00000 11111 10101"))
    assert result["characters"] == 3
    assert result["bitCounts"] == [2, 1, 2, 1, 2]
    assert len(result["deltaBitCounts"]) == 5


def test_fork_recursion_depth_enforced() -> None:
    from pychef import ExecutionLimitError, ExecutionPolicy

    # Max recursion depth = 2. 3 nested forks should fail.
    policy = ExecutionPolicy(max_recursion_depth=2)
    recipe = [
        {"op": "Fork", "args": [",", ","]},
        {"op": "Fork", "args": [":", ":"]},
        {"op": "Fork", "args": [";", ";"]},
        {"op": "To Upper case"},
        {"op": "Merge"},
        {"op": "Merge"},
        {"op": "Merge"},
    ]
    with pytest.raises(ExecutionLimitError) as exc_info:
        Chef(policy=policy).bake("a:b,c:d", recipe)
    assert exc_info.value.limit == "max_recursion_depth"


def test_fork_branches_limit_enforced() -> None:
    from pychef import ExecutionLimitError, ExecutionPolicy

    policy = ExecutionPolicy(max_branches=3)
    # 5 items to fork
    recipe = [
        {"op": "Fork", "args": [",", ","]},
        {"op": "To Upper case"},
        {"op": "Merge"},
    ]
    with pytest.raises(ExecutionLimitError) as exc_info:
        Chef(policy=policy).bake("1,2,3,4,5", recipe)
    assert exc_info.value.limit == "max_branches"


def test_infinite_jump_loop_stopped_by_max_steps() -> None:
    from pychef import ExecutionLimitError, ExecutionPolicy

    policy = ExecutionPolicy(max_steps=20)
    recipe = [
        {"op": "Label", "args": ["loop"]},
        {"op": "Jump", "args": ["loop", 1000]},
    ]
    with pytest.raises(ExecutionLimitError) as exc_info:
        Chef(policy=policy).bake("test", recipe)
    assert exc_info.value.limit == "max_steps"


def test_fork_large_delimiter_checked_against_policy() -> None:
    from pychef import ExecutionLimitError, ExecutionPolicy

    policy = ExecutionPolicy(max_input_bytes=100)
    huge_delim = "X" * 1000
    recipe = [
        {"op": "Fork", "args": [huge_delim, "\n"]},
        {"op": "To Upper case"},
        {"op": "Merge"},
    ]
    with pytest.raises(ExecutionLimitError) as exc_info:
        Chef(policy=policy).bake("hello", recipe)
    assert exc_info.value.limit == "max_input_bytes"


def test_jump_nonexistent_label_handled_gracefully() -> None:
    # Jumps to nonexistent label should not crash with KeyError
    recipe = [
        {"op": "Jump", "args": ["missing_label", 5]},
        {"op": "To Upper case"},
    ]
    res = Chef().bake("hello", recipe)
    assert res == "HELLO"
