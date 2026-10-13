"""Execution policy, shared budgets, structured errors, flow control and delimiters."""

from __future__ import annotations

import json
import threading

import pytest

from pychef import (
    Chef,
    ExecutionLimitError,
    ExecutionPolicy,
    ExecutionTimeoutError,
    InvalidOperationArgumentsError,
    OperationError,
    PyChefError,
    Recipe,
    bake,
)
from pychef.execution import ExecutionContext, NetworkPolicy
from pychef.recipe import _binary_delimiter

FORK = {"op": "Fork", "args": ["\n", "\n", False]}
MERGE = {"op": "Merge", "args": [True]}


# --- policy validation -------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["max_input_bytes", "max_output_bytes", "max_steps", "max_recursion_depth", "max_branches"],
)
@pytest.mark.parametrize("bad", [-1, 1.5, "10", True])
def test_policy_rejects_invalid_limits(field: str, bad: object) -> None:
    with pytest.raises(ValueError):
        ExecutionPolicy(**{field: bad})  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize("bad", [0, -1, "1", True])
def test_policy_rejects_invalid_deadline(bad: object) -> None:
    with pytest.raises(ValueError):
        ExecutionPolicy(cooperative_deadline_seconds=bad)  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]


def test_policy_profiles() -> None:
    assert ExecutionPolicy().allow_network is False
    assert ExecutionPolicy.permissive().allow_network is True
    untrusted = ExecutionPolicy.untrusted()
    assert not untrusted.allow_network and untrusted.max_steps is not None
    safe_with_unrestricted = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted())
    assert safe_with_unrestricted.network.mode == "unrestricted"
    assert safe_with_unrestricted.allow_network is True


def test_policy_with_overrides_network_source_of_truth() -> None:
    safe = ExecutionPolicy.safe()
    assert safe.network.mode == "disabled"
    assert safe.allow_network is False

    overridden = safe.with_overrides(network=NetworkPolicy.unrestricted())
    assert overridden.network.mode == "unrestricted"
    assert overridden.allow_network is True

    unrestricted = ExecutionPolicy.unrestricted()
    assert unrestricted.network.mode == "unrestricted"
    assert unrestricted.allow_network is True

    locked = unrestricted.with_overrides(network=NetworkPolicy.disabled())
    assert locked.network.mode == "disabled"
    assert locked.allow_network is False


def test_policy_with_overrides_none_and_large_limits() -> None:
    safe = ExecutionPolicy.safe()
    # Explicit None must NOT fall back to safe() default (512 MiB)
    unlimited_mem = safe.with_overrides(max_memory_bytes=None)
    assert unlimited_mem.max_memory_bytes is None

    gigabytes_64 = 64 * 1024**3
    large_mem = safe.with_overrides(max_memory_bytes=gigabytes_64)
    assert large_mem.max_memory_bytes == gigabytes_64

    # max_steps override to None
    untrusted = ExecutionPolicy.untrusted()
    assert untrusted.max_steps == 10000
    unlimited_steps = untrusted.with_overrides(max_steps=None)
    assert unlimited_steps.max_steps is None


def test_policy_backward_compatible_allow_network_and_conflicts() -> None:
    policy = ExecutionPolicy(allow_network=True)
    assert policy.allow_network is True
    assert policy.network.mode == "public_only"

    # Conflicting configuration raises ValueError
    with pytest.raises(ValueError, match="Conflicting network configuration"):
        ExecutionPolicy(allow_network=True, network=NetworkPolicy.disabled())

    with pytest.raises(ValueError, match="Conflicting network configuration"):
        ExecutionPolicy(allow_network=False, network=NetworkPolicy.unrestricted())

    # with_overrides with allow_network
    toggled = ExecutionPolicy.safe().with_overrides(allow_network=True)
    assert toggled.allow_network is True
    assert toggled.network.mode == "public_only"


def test_policy_and_context_are_mutually_exclusive() -> None:
    context = ExecutionContext(policy=ExecutionPolicy())
    with pytest.raises(ValueError):
        Recipe(["To Hex"]).execute("a", policy=ExecutionPolicy(), context=context)


# --- limits --------------------------------------------------------------------


def test_input_limit_counts_utf8_bytes_for_text_and_bytes() -> None:
    policy = ExecutionPolicy(max_input_bytes=3)
    assert bake(b"abc", ["To Hex"], policy=policy) == "61 62 63"
    assert bake("abc", ["To Hex"], policy=policy) == "61 62 63"
    for value in (b"abcd", "abcd", "äö"):  # "äö" is 4 UTF-8 bytes
        with pytest.raises(ExecutionLimitError) as info:
            bake(value, ["To Hex"], policy=policy)
        assert info.value.limit == "max_input_bytes"


def test_output_limit_after_operation() -> None:
    with pytest.raises(ExecutionLimitError) as info:
        bake(b"abcd", ["To Hex"], policy=ExecutionPolicy(max_output_bytes=8))
    assert info.value.limit == "max_output_bytes"
    assert info.value.operation_name == "To Hex"
    assert info.value.step_index == 0


def test_output_limit_applies_to_fork_merge() -> None:
    recipe = [FORK, {"op": "To Hex", "args": ["None"]}, MERGE]
    with pytest.raises(ExecutionLimitError):
        bake("aa\nbb\ncc", recipe, policy=ExecutionPolicy(max_output_bytes=8))


def test_output_limit_accounts_for_large_merge_delimiters() -> None:
    # Parts are small (1 byte each), but delimiter is 100 bytes
    large_delimiter = "=" * 100
    fork_step = {"op": "Fork", "args": ["\n", large_delimiter, False]}
    recipe = [fork_step, "To Upper case", MERGE]
    with pytest.raises(ExecutionLimitError) as info:
        bake("a\nb", recipe, policy=ExecutionPolicy(max_output_bytes=50))
    assert info.value.limit == "max_output_bytes"


def test_output_limit_applies_to_subsection_prefix_suffix() -> None:
    # Prefix and suffix bytes must count towards output budget
    sub = {"op": "Subsection", "args": ["x", True, False, False]}
    recipe = [sub, "To Upper case", MERGE]
    with pytest.raises(ExecutionLimitError) as info:
        bake(
            "prefix_long_" * 10 + "x" + "suffix_long_" * 10,
            recipe,
            policy=ExecutionPolicy(max_output_bytes=50),
        )
    assert info.value.limit == "max_output_bytes"


def test_step_budget_counts_all_steps() -> None:
    recipe = ["To Hex", "From Hex", "To Hex"]
    assert bake("a", recipe, policy=ExecutionPolicy(max_steps=3)) == "61"
    with pytest.raises(ExecutionLimitError) as info:
        bake("a", recipe, policy=ExecutionPolicy(max_steps=2))
    assert info.value.limit == "max_steps"


def test_repeated_jumps_count_toward_global_budget() -> None:
    recipe = [
        {"op": "Label", "args": ["x"]},
        {"op": "Jump", "args": ["x", 1000]},
    ]
    assert bake("a", recipe) == "a"  # legacy: bounded by the jump limit only
    with pytest.raises(ExecutionLimitError) as info:
        bake("a", recipe, policy=ExecutionPolicy(max_steps=50))
    assert info.value.limit == "max_steps"


def test_budget_is_shared_across_nested_recipes() -> None:
    recipe = [FORK, "To Hex", MERGE]
    # 1 fork step + 3 parts * 1 inner step + (merge counted) -> exceeds 4 only when shared
    with pytest.raises(ExecutionLimitError) as info:
        bake("a\nb\nc\nd\ne", recipe, policy=ExecutionPolicy(max_steps=4))
    assert info.value.limit == "max_steps"
    assert info.value.branch_path == (0,)


def test_branch_budget() -> None:
    recipe = [FORK, "To Hex", MERGE]
    assert bake("a\nb", recipe, policy=ExecutionPolicy(max_branches=2)) == "61\n62"
    with pytest.raises(ExecutionLimitError) as info:
        bake("a\nb\nc", recipe, policy=ExecutionPolicy(max_branches=2))
    assert info.value.limit == "max_branches"


def test_branch_budget_not_reset_by_nested_forks() -> None:
    recipe = [
        FORK,
        {"op": "Fork", "args": [",", ",", False]},
        "To Hex",
        MERGE,
        MERGE,
    ]
    # outer 2 branches + inner 2*2 branches = 6 > 5
    with pytest.raises(ExecutionLimitError):
        bake("a,b\nc,d", recipe, policy=ExecutionPolicy(max_branches=5))
    assert bake("a,b\nc,d", recipe, policy=ExecutionPolicy(max_branches=6)) == "61,62\n63,64"


def test_recursion_depth_nested_forks() -> None:
    recipe = [FORK, FORK, FORK, "To Hex", MERGE, MERGE, MERGE]
    assert bake("a", recipe, policy=ExecutionPolicy(max_recursion_depth=3)) == "61"
    with pytest.raises(ExecutionLimitError) as info:
        bake("a", recipe, policy=ExecutionPolicy(max_recursion_depth=2))
    assert info.value.limit == "max_recursion_depth"


def test_nested_subsections_share_budget_and_depth() -> None:
    sub = {"op": "Subsection", "args": ["a", True, True, False]}
    recipe = [sub, sub, "To Upper case", MERGE, MERGE]
    assert bake("aaa", recipe, policy=ExecutionPolicy(max_recursion_depth=2)) == "AAA"
    with pytest.raises(ExecutionLimitError):
        bake("aaa", recipe, policy=ExecutionPolicy(max_recursion_depth=1))


def test_limit_errors_not_swallowed_by_ignore_errors() -> None:
    recipe = [{"op": "Fork", "args": ["\n", "\n", True]}, "To Hex", MERGE]
    with pytest.raises(ExecutionLimitError):
        bake("a\nb\nc", recipe, policy=ExecutionPolicy(max_branches=1))


def test_errors_inside_branch_ignored_when_requested() -> None:
    bad = {"op": "Change IP format", "args": ["Dotted Decimal", "Decimal"]}
    assert bake("zz\n1.2.3.4", [{"op": "Fork", "args": ["\n", "\n", True]}, bad, MERGE]) == (
        "zz\n16909060"
    )
    with pytest.raises(OperationError):
        bake("zz\n1.2.3.4", [FORK, bad, MERGE])


def test_deadline_is_cooperative_between_steps() -> None:
    context = ExecutionContext(policy=ExecutionPolicy(cooperative_deadline_seconds=0.001))
    context._started -= 10  # simulate elapsed time
    with pytest.raises(ExecutionTimeoutError) as info:
        Recipe(["To Hex"]).execute("a", context=context)
    assert info.value.error_code == "deadline_exceeded"
    assert isinstance(info.value, ExecutionLimitError)
    assert isinstance(info.value, TimeoutError)


def test_cancellation() -> None:
    context = ExecutionContext()
    context.cancel()
    with pytest.raises(ExecutionLimitError) as info:
        Recipe(["To Hex"]).execute("a", context=context)
    assert info.value.limit == "cancelled"


def test_shared_context_accumulates_across_executions() -> None:
    context = ExecutionContext(policy=ExecutionPolicy(max_steps=3))
    recipe = Recipe(["To Hex", "From Hex"])
    recipe.execute("a", context=context)
    with pytest.raises(ExecutionLimitError):
        recipe.execute("a", context=context)


def test_execution_state_is_per_execution_not_global() -> None:
    results: list[object] = []

    def worker() -> None:
        results.append(bake("abc", ["To Hex"], policy=ExecutionPolicy(max_steps=1)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [thread.start() for thread in threads]
    [thread.join() for thread in threads]
    assert results == ["61 62 63"] * 8


# --- structured errors ---------------------------------------------------------


def test_operation_error_is_structured_and_chained() -> None:
    with pytest.raises(OperationError) as info:
        bake(
            "zz",
            [
                "To Hex",
                "To Upper case",
                {"op": "From Base64", "args": ["A-Za-z0-9+/=", False, True]},
            ],
        )
    error = info.value
    assert isinstance(error, PyChefError)
    assert error.operation_name == error.operation == "From Base64"
    assert error.step_index == 2
    assert error.error_code == "operation_failed"
    data = error.to_dict()
    json.dumps(data)
    assert data["step_index"] == 2 and data["operation_name"] == "From Base64"
    assert error.cause is error.__cause__ or error.cause is None


def test_error_step_index_in_branch() -> None:
    with pytest.raises(OperationError) as info:
        bake("zz", [FORK, {"op": "Change IP format", "args": ["Dotted Decimal", "Decimal"]}, MERGE])
    assert info.value.step_index == 1
    assert info.value.branch_path == (0,)
    assert info.value.execution_id


def test_bake_result_captures_limit_error_without_raising() -> None:
    result = Chef().bake_result(
        "a", ["To Hex"], raise_errors=False, policy=ExecutionPolicy(max_steps=0)
    )
    assert isinstance(result.error, ExecutionLimitError)


def test_error_messages_do_not_leak_arguments() -> None:
    secret = "SuperSecretKey123"
    with pytest.raises(OperationError) as info:
        bake(
            b"short",
            [
                {
                    "op": "AES Decrypt",
                    "args": [
                        {"option": "UTF8", "string": secret},
                        {"option": "Hex", "string": "00" * 16},
                        "CBC",
                        "Raw",
                        "Raw",
                    ],
                }
            ],
        )
    assert secret not in str(info.value)
    assert secret not in json.dumps(info.value.to_dict())


def test_error_messages_sanitize_exceptions_containing_secret_argument() -> None:
    secret_pass = "MySecretPassphrase123"
    recipe = [
        {
            "op": "PGP Decrypt",
            "args": ["invalid-key", secret_pass],
        }
    ]
    with pytest.raises(OperationError) as info:
        bake("encrypted", recipe)
    assert secret_pass not in str(info.value)
    assert secret_pass not in info.value.message
    assert secret_pass not in json.dumps(info.value.to_dict())


# --- flow control --------------------------------------------------------------


def test_empty_recipe_and_input() -> None:
    assert Recipe([]).execute("abc") == ("abc", 0)
    assert bake("", ["To Hex"]) == ""
    assert bake(b"", [FORK, "To Hex", MERGE]) == b"" or bake(b"", [FORK, "To Hex", MERGE]) == ""


def test_disabled_steps_and_comments() -> None:
    recipe = [{"op": "To Hex", "disabled": True}, {"op": "Comment", "args": ["x"]}, "To Upper case"]
    assert Recipe(recipe).execute("ab") == ("AB", 3)


def test_breakpoint_stops_and_reports_progress() -> None:
    value, progress = Recipe(
        ["To Hex", {"op": "To Upper case", "breakpoint": True}, "To Hex"]
    ).execute("a")
    assert (value, progress) == ("61", 1)


def test_return_stops_execution() -> None:
    assert Recipe(["To Hex", "Return", "To Upper case"]).execute("ab") == ("61 62", 2)


def test_label_and_conditional_jump_loop() -> None:
    recipe = [
        {"op": "Label", "args": ["l"]},
        {
            "op": "Find / Replace",
            "args": [{"option": "Regex", "string": "a"}, "b", True, False, True, False],
        },
        {"op": "Conditional Jump", "args": ["a", False, "l", 10]},
    ]
    assert bake("aaa", recipe) == "bbb"


def test_multiple_jumps_and_jump_limit() -> None:
    recipe = [
        {"op": "Label", "args": ["l"]},
        {
            "op": "Find / Replace",
            "args": [{"option": "Regex", "string": "$"}, "x", False, False, False, False],
        },
        {"op": "Jump", "args": ["l", 3]},
    ]
    assert bake("", recipe) == "xxxx"


def test_unknown_label_falls_through() -> None:
    assert bake("a", [{"op": "Jump", "args": ["nowhere", 3]}, "To Hex"]) == "61"


@pytest.mark.parametrize("bad", [-1, "abc", None, True])
def test_invalid_jump_limits(bad: object) -> None:
    recipe = [{"op": "Label", "args": ["l"]}, {"op": "Jump", "args": ["l", bad]}]
    with pytest.raises(InvalidOperationArgumentsError) as info:
        bake("a", recipe)
    assert info.value.step_index == 1
    assert isinstance(info.value, ValueError)


def test_invalid_regex_is_structured() -> None:
    for recipe in (
        [{"op": "Conditional Jump", "args": ["(", False, "l", 3]}],
        [{"op": "Register", "args": ["(", True, False, False]}],
        [{"op": "Subsection", "args": ["(", True, True, False]}, MERGE],
    ):
        with pytest.raises(InvalidOperationArgumentsError) as info:
            bake("a", recipe)
        assert info.value.error_code == "invalid_arguments"
        assert info.value.cause is not None


def test_register_large_value_and_escapes() -> None:
    big = "x" * 200_000
    recipe = [
        {"op": "Register", "args": ["(.*)", True, False, False]},
        {
            "op": "Find / Replace",
            "args": [{"option": "Regex", "string": "^"}, "$R0", False, False, False, False],
        },
    ]
    assert bake(big, recipe) == big + big


def test_nested_fork_and_subsection_combined_with_unicode_and_binary() -> None:
    recipe = [
        FORK,
        {"op": "Subsection", "args": ["ä", True, True, False]},
        "To Upper case",
        MERGE,
        MERGE,
    ]
    assert bake("bäb\nöä", recipe) == "bÄb\nöÄ"
    assert str(bake(b"\xff\xfeabc\n\x00", ["To Hex"])).startswith("ff fe")  # binary input, no crash


def test_fork_with_many_parts_is_bounded_by_policy() -> None:
    recipe = [{"op": "Fork", "args": ["", "", False]}, "To Hex", MERGE]
    text = "x" * 5000
    with pytest.raises(ExecutionLimitError):
        bake(text, recipe, policy=ExecutionPolicy(max_branches=100))
    with pytest.raises(ExecutionLimitError):
        bake(text, recipe, policy=ExecutionPolicy(max_steps=100))


def test_catastrophic_regex_documented_limit_is_not_pretended() -> None:
    # Python's ``re`` cannot be interrupted; only the cooperative budgets apply.
    # A benign pattern must work and an invalid one must be reported structurally.
    assert bake("aaaa", [{"op": "Conditional Jump", "args": ["a+", False, "", 1]}]) == "aaaa"


# --- tracing -------------------------------------------------------------------


def test_trace_records_types_and_sizes_not_data() -> None:
    result = Chef().bake_result("äb", ["To Hex", "From Hex"], trace=True)
    first, second = result.trace
    assert (first.operation, first.step_index) == ("To Hex", 0)
    assert (first.input_type, first.output_type) == ("string", "string")
    assert first.input_size == 3  # UTF-8 bytes
    assert second.output_size == 3
    assert not hasattr(first, "preview")
    assert Chef().bake_result("a", ["To Hex"]).trace == ()


def test_trace_limit() -> None:
    with pytest.raises(ExecutionLimitError) as info:
        Chef().bake_result(
            "a", ["To Hex"] * 5, trace=True, policy=ExecutionPolicy(max_trace_bytes=400)
        )
    assert info.value.limit == "max_trace_bytes"


# --- delimiters (CyberChef Utils.parseEscapedChars semantics) --------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ä", "ä"),
        ("éÀ", "éÀ"),
        ("中文", "中文"),
        ("😀", "😀"),
        ("\\n", "\n"),
        ("\\r\\n", "\r\n"),
        ("\\t", "\t"),
        ("\\\\", "\\"),
        ("\\\\n", "\\n"),
        ("\\x41", "A"),
        ("\\xe4", "ä"),
        ("\\u00e4", "ä"),
        ("\\u{1F600}", "😀"),
        ("\\101", "A"),
        ("\\q", "\\q"),
        ("\\x4", "\\x4"),
        ("\\xZZ", "\\xZZ"),
        ("a\\", "a\\"),
        ("ä\\nö", "ä\nö"),
        ("\\u{110000}", "\\u{110000}"),
        ("", ""),
    ],
)
def test_binary_delimiter(raw: str, expected: str) -> None:
    assert _binary_delimiter(raw) == expected


def test_fork_with_unicode_delimiters() -> None:
    recipe = [{"op": "Fork", "args": ["ä", "→", False]}, "To Upper case", MERGE]
    assert bake("aäbäc", recipe) == "A→B→C"
