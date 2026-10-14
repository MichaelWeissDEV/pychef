"""Tests for pipeline tracing, preview truncation, and resource budgeting (Phase 6)."""

from __future__ import annotations

from typing import Any

import pytest

from pychef import (
    ExecutionLimitError,
    ExecutionPolicy,
    Pipeline,
)
from pychef.pipeline import _measure_trace_size, _truncate_preview


def test_trace_large_nested_dictionary() -> None:
    """_measure_trace_size handles large nested dictionaries safely."""
    nested: dict[str, Any] = {"level": 0}
    curr = nested
    for i in range(1, 50):
        curr["child"] = {"level": i, "data": "x" * 20}
        curr = curr["child"]

    size = _measure_trace_size(nested)
    assert size > 1000

    pipeline = Pipeline().apply(lambda d: {**d, "processed": True})
    traces = pipeline.trace(nested)
    assert len(traces) == 1
    assert traces[0].input_size > 1000


def test_trace_shared_object_references() -> None:
    """_measure_trace_size does not double-count shared object references."""
    shared = {"shared_key": "x" * 500}
    data = {
        "ref1": shared,
        "ref2": shared,
        "ref3": shared,
    }
    size = _measure_trace_size(data)
    # 500 bytes for shared string + container overheads; must not count 3 * 500 bytes
    assert size < 1000


def test_trace_circular_container() -> None:
    """_measure_trace_size and Pipeline.trace handle circular containers without RecursionError."""
    circular: dict[str, Any] = {"name": "loop"}
    circular["self"] = circular

    # Must terminate without RecursionError
    size = _measure_trace_size(circular)
    assert size > 0

    pipeline = Pipeline().apply(lambda d: d)
    traces = pipeline.trace(circular)
    assert len(traces) == 1
    assert traces[0].name == "<lambda>"


def test_trace_utf8_preview_exact_bytes() -> None:
    """_truncate_preview slices multi-byte UTF-8 without raising UnicodeDecodeError."""
    # "🎉" is 4 bytes: 0xf0 0x9f 0x8e 0x89
    text = "🎉" * 10  # 40 bytes
    truncated, was_trunc = _truncate_preview(text, 10)
    assert was_trunc is True
    # 10 bytes can hold at most 2 4-byte characters (8 bytes)
    assert len(truncated.encode("utf-8")) <= 10
    assert truncated == "🎉🎉"

    # Truncation with limit 0
    trunc_zero, was_trunc_zero = _truncate_preview(text, 0)
    assert was_trunc_zero is True
    assert trunc_zero == ""


def test_trace_binary_preview() -> None:
    """_truncate_preview accurately truncates raw byte sequences."""
    data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    truncated, was_trunc = _truncate_preview(data, 4)
    assert was_trunc is True
    assert truncated == b"\x00\x01\x02\x03"

    # Limit 0
    trunc_zero, was_trunc_zero = _truncate_preview(data, 0)
    assert was_trunc_zero is True
    assert trunc_zero == b""


def test_trace_budget_counts_stored_data() -> None:
    """Trace budget charges stored preview bytes rather than logical object size."""
    large_payload = "A" * 10_000  # 10,000 bytes
    pipeline = Pipeline().apply(lambda x: x.lower())

    # With a small max_trace_bytes (e.g. 500 bytes), full payload exhausts budget
    policy = ExecutionPolicy(max_trace_bytes=500)
    with pytest.raises(ExecutionLimitError) as exc_info:
        pipeline.trace(large_payload, policy=policy)
    assert exc_info.value.limit == "max_trace_bytes"

    # With max_preview_bytes=50, stored bytes is small enough (50 + 50 + 64 < 500)
    traces = pipeline.trace(large_payload, policy=policy, max_preview_bytes=50)
    assert len(traces) == 1
    assert traces[0].truncated is True
    assert len(traces[0].input) == 50
    assert len(traces[0].output) == 50
    assert traces[0].input_size == 10_000
    assert traces[0].output_size == 10_000


def test_streaming_does_not_eagerly_consume_iterator() -> None:
    """Pipeline.iter_transform does not eagerly pull items from the source iterable."""
    consumed_count = 0

    def item_generator() -> Any:
        nonlocal consumed_count
        for i in range(10):
            consumed_count += 1
            yield f"item-{i}"

    pipeline = Pipeline().apply(lambda x: x.upper())
    stream = pipeline.iter_transform(item_generator())

    # Creating the stream should not consume anything
    assert consumed_count == 0

    first = next(stream)
    assert first == "ITEM-0"
    assert consumed_count == 1

    second = next(stream)
    assert second == "ITEM-1"
    assert consumed_count == 2
