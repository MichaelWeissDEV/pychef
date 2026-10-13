"""Tests for Pipeline streaming via iter_transform."""

from __future__ import annotations

import pytest

from pychef import ExecutionLimitError, ExecutionPolicy, Pipeline


def test_pipeline_iter_transform_basic() -> None:
    pipeline = Pipeline().apply(lambda x: x.upper()).apply(lambda x: f"[{x}]")
    inputs = ["apple", "banana", "cherry"]
    stream = pipeline.iter_transform(inputs)
    assert hasattr(stream, "__next__")
    assert next(stream) == "[APPLE]"
    assert next(stream) == "[BANANA]"
    assert next(stream) == "[CHERRY]"


def test_pipeline_iter_transform_shares_budget() -> None:
    # 2 stages per item. With max_steps=5, 3rd item (stage 1 = step 5, stage 2 = step 6) should fail
    pipeline = Pipeline().apply(lambda x: x + "1").apply(lambda x: x + "2")
    policy = ExecutionPolicy(max_steps=4)
    items = ["a", "b", "c"]
    iterator = pipeline.iter_transform(items, policy=policy)
    assert next(iterator) == "a12"  # 2 steps
    assert next(iterator) == "b12"  # 4 steps
    with pytest.raises(ExecutionLimitError) as exc_info:
        next(iterator)  # step 5 -> fails
    assert exc_info.value.limit == "max_steps"


def test_pipeline_transform_many_delegates_to_iter() -> None:
    pipeline = Pipeline().apply(str.strip).apply(str.lower)
    res = pipeline.transform_many(["  HELLO ", " WORLD  "])
    assert res == ("hello", "world")
