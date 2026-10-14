"""One execution, one context: nested bake/Pipeline/Chef/ops calls share budgets."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from pychef import (
    Chef,
    ExecutionContext,
    ExecutionLimitError,
    ExecutionPolicy,
    ExecutionTimeoutError,
    Pipeline,
    bake,
)
from pychef.execution import current_context, current_policy
from pychef.ops import md5, run_operation, sha256, to_base64, to_hex, using_policy


def test_nested_direct_operation_shares_step_budget() -> None:
    pipeline = Pipeline().apply(to_base64)
    assert pipeline(b"ABC", policy=ExecutionPolicy(max_steps=2)) == "QUJD"
    with pytest.raises(ExecutionLimitError) as excinfo:
        pipeline(b"ABC", policy=ExecutionPolicy(max_steps=1))
    assert excinfo.value.limit == "max_steps"


def test_every_entry_point_shares_the_budget_when_nested() -> None:
    policy = ExecutionPolicy(max_steps=1)  # the apply stage alone uses the single step
    for inner in (
        lambda v: bake(v, ["To Base64"]),
        lambda v: Chef().bake(v, ["To Base64"]),
        lambda v: Pipeline().to_base64()(v),
        lambda v: run_operation("To Base64", v),
        lambda v: sha256(v),
    ):
        with pytest.raises(ExecutionLimitError):
            Pipeline().apply(inner)(b"ABC", policy=policy)
        assert Pipeline().apply(inner)(b"ABC", policy=ExecutionPolicy(max_steps=2))


def test_nested_direct_operation_shares_deadline() -> None:
    pipeline = Pipeline().apply(lambda v: (time.sleep(0.15), v)[1]).apply(to_base64)
    with pytest.raises(ExecutionTimeoutError):
        pipeline(b"x", policy=ExecutionPolicy(cooperative_deadline_seconds=0.05))


def test_nested_direct_operation_shares_execution_id_and_trace() -> None:
    seen: list[ExecutionContext | None] = []

    def capture(value: bytes) -> str:
        seen.append(current_context())
        return to_base64(value)

    context = ExecutionContext(policy=ExecutionPolicy.safe(), trace_enabled=True)
    Pipeline().apply(capture).transform(b"ABC", context=context)
    assert seen == [context]
    assert [step.operation for step in context.trace] == ["To Base64", "capture"]
    assert context.steps == 2  # counted once each, no double accounting


def test_nested_direct_operation_shares_branch_path() -> None:
    context = ExecutionContext(policy=ExecutionPolicy.safe(), trace_enabled=True)
    pipeline = Pipeline().concat(
        Pipeline().apply(to_base64), Pipeline().apply(to_hex), separator=""
    )
    pipeline.transform(b"A", context=context)
    nested = [step for step in context.trace if step.operation in {"To Base64", "To Hex"}]
    assert [step.branch_path for step in nested] == [(0,), (0,)]
    assert context.branches == 2


def test_direct_operation_inside_concat_uses_parent_context() -> None:
    pipeline = Pipeline().concat(
        Pipeline().apply(to_base64), Pipeline().apply(to_base64), separator=""
    )
    # concat 1 + 2 branch apply stages + 2 nested operations
    assert pipeline(b"A", policy=ExecutionPolicy(max_steps=5)) == "QQ==QQ=="
    with pytest.raises(ExecutionLimitError):
        pipeline(b"A", policy=ExecutionPolicy(max_steps=4))


def test_nested_operation_does_not_reset_policy() -> None:
    seen: list[ExecutionPolicy | None] = []
    policy = ExecutionPolicy.unrestricted()
    Pipeline().apply(lambda v: seen.append(current_policy()) or to_base64(v))(b"A", policy=policy)
    assert seen == [policy]


def test_nested_operation_rejects_conflicting_policy() -> None:
    outer = ExecutionPolicy(max_steps=10)
    escalate = ExecutionPolicy.unrestricted()
    for inner in (
        lambda v: run_operation("To Base64", v, policy=escalate),
        lambda v: bake(v, ["To Base64"], policy=escalate),
        lambda v: Pipeline().to_base64()(v, policy=escalate),
        lambda v: Chef(policy=escalate).bake(v, ["To Base64"]),
    ):
        with pytest.raises(ValueError, match="running execution"):
            Pipeline().apply(inner)(b"A", policy=outer)

    def enter_block(value: bytes) -> str:
        with using_policy(escalate):
            return to_base64(value)

    with pytest.raises(ValueError, match="running execution"):
        Pipeline().apply(enter_block)(b"A", policy=outer)

    def same_policy(value: bytes) -> str:
        with using_policy(outer):
            return to_base64(value)

    assert Pipeline().apply(same_policy)(b"A", policy=outer) == "QQ=="


def test_nested_operation_context_restored_after_error() -> None:
    def failing(value: bytes) -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        Pipeline().apply(failing)(b"A")
    with pytest.raises(ExecutionLimitError):
        Pipeline().apply(to_base64)(b"A", policy=ExecutionPolicy(max_steps=1))
    assert current_context() is None
    assert current_policy() is None


def test_separate_top_level_operations_have_independent_contexts() -> None:
    policy = ExecutionPolicy(max_steps=1)
    with using_policy(policy):
        for _ in range(5):  # each independent top-level call has a fresh one-step budget
            assert to_base64(b"A") == "QQ=="
            assert sha256(b"A")


def test_nested_execution_context_is_thread_local() -> None:
    results: dict[str, object] = {}

    def worker() -> None:
        results["context"] = current_context()
        results["value"] = to_base64(b"A")  # independent top-level call in a new thread

    def inner(value: bytes) -> str:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        return to_base64(value)

    assert Pipeline().apply(inner)(b"A", policy=ExecutionPolicy(max_steps=2)) == "QQ=="
    assert results == {"context": None, "value": "QQ=="}


def test_nested_execution_context_async_task_behavior() -> None:
    async def task() -> object:
        return current_context()

    async def main() -> list[object]:
        return list(await asyncio.gather(task(), task()))

    captured: list[object] = []

    def inner(value: bytes) -> bytes:
        captured.extend(asyncio.run(main()))
        return value

    context = ExecutionContext(policy=ExecutionPolicy.safe())
    Pipeline().apply(inner).transform(b"A", context=context)
    # Tasks copy the caller's contextvars: they see (and would share) the same context.
    assert captured == [context, context]


def test_explicit_none_limits_stay_disabled_inside_nested_calls() -> None:
    policy = ExecutionPolicy(
        max_steps=None, max_output_bytes=None, cooperative_deadline_seconds=None
    )
    pipeline = Pipeline().apply(lambda v: to_base64(v)).apply(lambda v: sha256(v))
    for _ in range(3):
        assert pipeline(b"A" * 100, policy=policy)


def test_input_and_output_limits_apply_to_nested_calls() -> None:
    with pytest.raises(ExecutionLimitError) as excinfo:
        Pipeline().apply(to_base64)(b"ABCDEF", policy=ExecutionPolicy(max_output_bytes=4))
    assert excinfo.value.limit == "max_output_bytes"
    with pytest.raises(ExecutionLimitError):
        Pipeline().apply(md5)(b"A", policy=ExecutionPolicy(max_output_bytes=8))


def test_trace_byte_limit_applies_to_nested_calls() -> None:
    context = ExecutionContext(policy=ExecutionPolicy(max_trace_bytes=100), trace_enabled=True)
    with pytest.raises(ExecutionLimitError) as excinfo:
        Pipeline().apply(to_base64).transform(b"A", context=context)
    assert excinfo.value.limit == "max_trace_bytes"


def test_nested_recursion_depth_is_shared() -> None:
    inner = Pipeline().apply(to_base64)
    nested = Pipeline().concat(Pipeline().concat(inner, separator=""), separator="")
    assert nested(b"A", policy=ExecutionPolicy(max_recursion_depth=2)) == "QQ=="
    with pytest.raises(ExecutionLimitError):
        nested(b"A", policy=ExecutionPolicy(max_recursion_depth=1))
