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


def test_isolated_worker_platform_support_check() -> None:
    import sys

    supported = IsolatedWorker.is_hard_memory_limit_supported()
    if sys.platform.startswith("linux"):
        import resource

        expected = hasattr(resource, "RLIMIT_AS") or hasattr(resource, "RLIMIT_DATA")
        assert supported is expected
    else:
        assert supported is False


def test_isolated_worker_hard_limit_on_unsupported_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        IsolatedWorker, "is_hard_memory_limit_supported", classmethod(lambda cls: False)
    )
    with pytest.raises(RuntimeError, match="Hard process memory limits are not supported"):
        IsolatedWorker(hard_memory_limit_bytes=100 * 1024 * 1024)

    worker = IsolatedWorker()
    with pytest.raises(RuntimeError, match="Hard process memory limits are not supported"):
        worker.run("abc", ["To Hex"], hard_memory_limit_bytes=100 * 1024 * 1024)


def test_isolated_worker_invalid_hard_limit_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        IsolatedWorker, "is_hard_memory_limit_supported", classmethod(lambda cls: True)
    )
    with pytest.raises(ValueError, match="positive integer"):
        IsolatedWorker(hard_memory_limit_bytes=-1)
    with pytest.raises(ValueError, match="positive integer"):
        IsolatedWorker(hard_memory_limit_bytes=0)


def test_isolated_worker_closed_raises() -> None:
    worker = IsolatedWorker()
    worker.close()
    with pytest.raises(RuntimeError, match="closed"):
        worker.run("abc", ["To Hex"])


def test_isolated_worker_trace_returned() -> None:
    worker = IsolatedWorker()
    res = worker.run("abc", ["To Hex"], trace=True)
    assert len(res.trace) == 1
    assert res.trace[0].operation == "To Hex"


def test_isolated_worker_unpicklable_exception_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    from typing import Any

    from pychef.worker import _worker_entry

    class DummyConn:
        def __init__(self) -> None:
            self.sent: list[dict[str, Any]] = []

        def send(self, data: dict[str, Any]) -> None:
            self.sent.append(data)

        def close(self) -> None:
            pass

    class UnpicklableError(Exception):
        def __reduce__(self) -> Any:
            raise TypeError("Cannot pickle this error")

    class BadRecipe:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise UnpicklableError("Something strange happened")

    monkeypatch.setattr("pychef.recipe.Recipe", BadRecipe)
    conn = DummyConn()
    _worker_entry(conn, "abc", ["To Hex"], ExecutionPolicy(), None, None, False)
    assert len(conn.sent) == 1
    assert conn.sent[0]["success"] is False
    assert conn.sent[0]["error"]["__unpicklable__"] is True
    assert conn.sent[0]["error"]["type"] == "UnpicklableError"


def test_isolated_worker_override_hard_limit_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Set unsupported platform
    monkeypatch.setattr(
        IsolatedWorker, "is_hard_memory_limit_supported", classmethod(lambda cls: False)
    )
    # A worker created with None can be explicitly run with hard_memory_limit_bytes=None
    worker = IsolatedWorker()
    res = worker.run("abc", ["To Hex"], hard_memory_limit_bytes=None)
    assert res.result == "61 62 63"


def test_chef_bake_result_isolated_raise_errors_false() -> None:
    from pychef import Chef

    chef = Chef(isolated=True)
    # Exceed step memory limit
    policy = ExecutionPolicy(max_memory_bytes=10)
    result = chef.bake_result("A" * 1000, ["To Hex"], policy=policy, raise_errors=False)
    assert result.error is not None
    assert isinstance(result.error, ExecutionLimitError)
    assert result.error.limit == "max_memory_bytes"
