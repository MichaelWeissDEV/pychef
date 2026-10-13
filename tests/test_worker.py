"""Tests for isolated worker execution."""

from __future__ import annotations

import pytest

from pychef import (
    ExecutionLimitError,
    ExecutionPolicy,
    ExecutionTimeoutError,
    IsolatedWorker,
    bake,
    bake_isolated,
)


def test_isolated_worker_basic_execution() -> None:
    res = bake_isolated("Hello World", ["To Hex"])
    assert res == "48 65 6c 6c 6f 20 57 6f 72 6c 64"


def test_isolated_worker_context_manager() -> None:
    with IsolatedWorker() as worker:
        out1 = worker.run("abc", ["To Base64"])
        out2 = worker.run("41 42", ["From Hex"])
        assert out1.result == "YWJj"
        assert out2.result == b"AB"


def test_isolated_worker_timeout_termination() -> None:
    worker = IsolatedWorker(timeout=0.02)
    # High cost Argon2 will take hundreds of ms in pure-Python
    recipe = [{"op": "Argon2", "args": [64, 50, 4, 1024, "argon2i"]}]
    with pytest.raises(ExecutionTimeoutError):
        worker.run("test password", recipe)


def test_isolated_worker_limit_error_propagated() -> None:
    policy = ExecutionPolicy(max_memory_bytes=100)
    with pytest.raises(ExecutionLimitError):
        bake_isolated("A" * 1000, ["To Hex"], policy=policy)


def test_bake_with_isolated_flag() -> None:
    res = bake("cyberchef", ["To Base64"], isolated=True)
    assert res == "Y3liZXJjaGVm"
