"""Regression tests for redirect-body handling, worker IPC deadlines, and branch contexts."""

from __future__ import annotations

import multiprocessing as mp
import os
import struct
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pychef import (
    ExecutionContext,
    ExecutionLimitError,
    ExecutionPolicy,
    ExecutionTimeoutError,
    IsolatedWorker,
    NetworkPolicy,
    Pipeline,
    bake,
)
from pychef.execution import current_policy
from pychef.worker import _recv_before_deadline

# --- 1.1 redirect bodies ----------------------------------------------------


class _SlowRedirectHandler(BaseHTTPRequestHandler):
    stalled = threading.Event()

    def do_GET(self) -> None:
        if self.path == "/slow-redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", str(10**9))
            self.end_headers()
            self.wfile.write(b"x" * 16)
            self.wfile.flush()
            # Never finish the advertised body; a client that drains it hangs.
            self.stalled.wait(20)
            return
        body = b"final"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def slow_redirect_server() -> Iterator[int]:
    _SlowRedirectHandler.stalled.clear()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SlowRedirectHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        _SlowRedirectHandler.stalled.set()
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("max_response_bytes", [1024, None])
def test_redirect_body_is_not_drained(
    slow_redirect_server: int, max_response_bytes: int | None
) -> None:
    policy = ExecutionPolicy(
        network=NetworkPolicy.unrestricted(
            timeout_seconds=15.0, max_response_bytes=max_response_bytes
        )
    )
    started = time.monotonic()
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{slow_redirect_server}/slow-redirect"],
            }
        ],
        policy=policy,
    )
    assert time.monotonic() - started < 10
    assert "final" in str(result)


# --- 1.2 worker IPC deadline ------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="relies on POSIX Connection framing")
def test_recv_before_deadline_times_out_on_partial_message() -> None:
    reader, writer = mp.Pipe(duplex=False)
    try:
        # A header announcing 1000 bytes followed by only 3 of them.
        os.write(writer.fileno(), struct.pack("!i", 1000) + b"abc")
        assert reader.poll(1)  # the old poll() + recv() sequence would now block forever
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            _recv_before_deadline(reader, 0.3, writer.close)
        assert time.monotonic() - started < 3
    finally:
        writer.close()
        reader.close()


def test_recv_before_deadline_returns_small_and_large_payloads() -> None:
    reader, writer = mp.Pipe(duplex=False)
    sender = threading.Thread(target=lambda: writer.send({"data": b"z" * 5_000_000}), daemon=True)
    sender.start()
    try:
        assert _recv_before_deadline(reader, 10)["data"] == b"z" * 5_000_000
    finally:
        sender.join()
        writer.close()
        reader.close()


def test_recv_before_deadline_reports_closed_peer() -> None:
    reader, writer = mp.Pipe(duplex=False)
    writer.close()
    with pytest.raises(EOFError):
        _recv_before_deadline(reader, 5)
    reader.close()


# --- 1.3 branch contexts ----------------------------------------------------


def test_concat_branches_share_step_budget() -> None:
    pipeline = Pipeline().concat(Pipeline().from_hex(), Pipeline().from_hex())
    # 1 concat step + 1 step in each branch = 3 steps
    assert pipeline("4142", policy=ExecutionPolicy(max_steps=3)) == b"ABAB"
    with pytest.raises(ExecutionLimitError) as excinfo:
        pipeline("4142", policy=ExecutionPolicy(max_steps=2))
    assert excinfo.value.limit == "max_steps"


def test_concat_branches_share_branch_budget_and_depth() -> None:
    pipeline = Pipeline().concat(Pipeline(), Pipeline(), Pipeline(), separator="")
    with pytest.raises(ExecutionLimitError):
        pipeline("a", policy=ExecutionPolicy(max_branches=2))
    nested = Pipeline().concat(
        Pipeline().concat(Pipeline().concat(Pipeline(), separator=""), separator=""), separator=""
    )
    assert nested("a", policy=ExecutionPolicy(max_recursion_depth=3)) == "a"
    with pytest.raises(ExecutionLimitError):
        nested("a", policy=ExecutionPolicy(max_recursion_depth=2))


def test_branches_keep_outer_policy_object() -> None:
    seen: list[object] = []

    def capture(value: object) -> object:
        seen.append(current_policy())
        return value

    inner = Pipeline().apply(capture)
    nested = Pipeline().concat(Pipeline().concat(inner, separator=""), inner, separator="")
    unrestricted = ExecutionPolicy.unrestricted()
    nested("a", policy=unrestricted)
    assert len(seen) == 2
    assert all(policy is unrestricted for policy in seen)


def test_branches_keep_outer_network_policy() -> None:
    branch = Pipeline().then("HTTP request", "GET", "http://127.0.0.1:9/")
    with pytest.raises(Exception, match="network access is not permitted"):
        Pipeline().concat(branch)("", policy=ExecutionPolicy.safe())
    # Permitted by the outer policy: the branch reaches the (closed) port instead of
    # being denied, so the failure is a connection error, not a permission error.
    allowed = ExecutionPolicy(network=NetworkPolicy.unrestricted(timeout_seconds=2.0))
    with pytest.raises(Exception) as excinfo:
        Pipeline().concat(branch)("", policy=allowed)
    assert "not permitted" not in str(excinfo.value)


def test_branches_keep_deadline_and_trace() -> None:
    slow = Pipeline().apply(lambda v: time.sleep(0.2) or v)
    pipeline = Pipeline().concat(slow, Pipeline().apply(str), separator="")
    with pytest.raises(Exception, match="deadline"):
        pipeline("4142", policy=ExecutionPolicy(cooperative_deadline_seconds=0.05))
    context = ExecutionContext(policy=ExecutionPolicy.safe(), trace_enabled=True)
    Pipeline().concat(Pipeline().to_hex(), Pipeline().to_hex(), separator="").transform(
        "AB", context=context
    )
    assert [step.branch_path for step in context.trace] == [(0,), (0,), ()]
    assert context.branches == 2


def test_stream_deadline_counts_consumer_time_and_steps_are_shared() -> None:
    decode = Pipeline().from_hex()
    stream = decode.iter_transform(
        iter(["41"] * 3), policy=ExecutionPolicy(cooperative_deadline_seconds=0.2)
    )
    assert next(stream) == b"A"
    time.sleep(0.3)  # slow consumer: the shared deadline keeps running
    with pytest.raises(ExecutionTimeoutError):
        next(stream)
    budget = ExecutionPolicy(max_steps=3)
    with pytest.raises(ExecutionLimitError):
        list(decode.iter_transform(["41"] * 5, policy=budget))
    unlimited = ExecutionPolicy(max_steps=None, cooperative_deadline_seconds=None)
    assert len(list(decode.iter_transform(["41"] * 50, policy=unlimited))) == 50


# --- 1.2 end to end ---------------------------------------------------------


def _stalling_worker_entry(conn: object, *_args: object) -> None:
    import os
    import struct
    import time

    fd = conn.fileno()  # type: ignore
    os.write(fd, struct.pack("!i", 1000) + b"abc")  # partial frame, then stall
    time.sleep(60)


@pytest.mark.skipif(sys.platform == "win32", reason="relies on POSIX Connection framing")
def test_isolated_worker_deadline_covers_partial_ipc_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pychef.worker as worker_module

    monkeypatch.setattr(worker_module, "_worker_entry", _stalling_worker_entry)
    worker = IsolatedWorker(timeout=1.5)
    started = time.monotonic()
    with pytest.raises(ExecutionTimeoutError):
        worker.run("41", ["From Hex"])
    assert time.monotonic() - started < 10
    assert worker._current_process is None
    assert not [p for p in mp.active_children() if p.is_alive()]


def _garbage_frame_entry(conn: object, *_args: object) -> None:
    conn.send_bytes(b"\x80garbage")  # type: ignore


def _abort_entry(conn: object, *_args: object) -> None:
    import os

    os._exit(3)


@pytest.mark.parametrize("entry", [_garbage_frame_entry, _abort_entry], ids=["garbage", "abort"])
@pytest.mark.parametrize("timeout", [20.0, None], ids=["deadline", "no-deadline"])
def test_isolated_worker_reports_broken_child_as_pychef_error(
    monkeypatch: pytest.MonkeyPatch, entry: object, timeout: float | None
) -> None:
    import pychef.worker as worker_module
    from pychef import PyChefError

    monkeypatch.setattr(worker_module, "_worker_entry", entry)
    policy = ExecutionPolicy(cooperative_deadline_seconds=None)
    worker = IsolatedWorker(timeout=timeout, policy=policy)
    with pytest.raises(PyChefError) as excinfo:
        worker.run("41", ["From Hex"])
    assert not isinstance(excinfo.value, ExecutionTimeoutError)
    assert "unpickl" not in type(excinfo.value).__name__.lower()
    assert worker._current_process is None
    assert not [p for p in mp.active_children() if p.is_alive()]


# --- worker deadline: finalised lifecycle -------------------------------------


def _silent_entry(conn: object, *_args: object) -> None:
    import time

    time.sleep(60)


def _stalled_large_frame_entry(conn: object, *_args: object) -> None:
    import os
    import struct
    import time

    fd = conn.fileno()  # type: ignore
    os.write(fd, struct.pack("!i", 50_000_000) + b"x" * 200_000)
    time.sleep(60)


def _no_reader_threads() -> bool:
    return not [t for t in threading.enumerate() if t.name == "pychef-worker-recv" and t.is_alive()]


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(
            _stalled_large_frame_entry,
            id="large-partial-frame",
            marks=pytest.mark.skipif(sys.platform == "win32", reason="POSIX Connection framing"),
        ),
        pytest.param(_silent_entry, id="silent-child"),
    ],
)
def test_worker_timeout_returns_promptly_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, entry: object
) -> None:
    import pychef.worker as worker_module

    monkeypatch.setattr(worker_module, "_worker_entry", entry)
    worker = IsolatedWorker(timeout=1.0)
    started = time.monotonic()
    with pytest.raises(ExecutionTimeoutError):
        worker.run("41", ["From Hex"])
    # deadline + bounded cleanup (termination grace and reader join), never the old 5 s join
    assert time.monotonic() - started < 1.0 + 1.0 + 3.0
    assert _no_reader_threads()
    assert worker._current_process is None
    assert not [p for p in mp.active_children() if p.is_alive()]


def test_blocked_reader_is_parked_not_waited_for(monkeypatch: pytest.MonkeyPatch) -> None:
    """A descendant holding the pipe's write end keeps the read blocked after the kill."""
    import pychef.worker as worker_module

    reader, writer = mp.Pipe(duplex=False)  # the writer plays the role of an inherited handle
    started = time.monotonic()
    try:
        with pytest.raises(worker_module._ReaderTimeout) as excinfo:
            _recv_before_deadline(reader, 0.2, None)
        assert excinfo.value.reader_still_blocked
        assert time.monotonic() - started < 0.2 + worker_module._READER_CLEANUP_SECONDS + 1.0
    finally:
        writer.close()  # releases the parked reader thread
    deadline = time.monotonic() + 5
    while worker_module._PARKED_READERS and time.monotonic() < deadline:
        worker_module._PARKED_READERS[:] = [
            i for i in worker_module._PARKED_READERS if i[0].is_alive()
        ]
        time.sleep(0.05)
    assert not worker_module._PARKED_READERS
    reader.close()


def test_worker_without_deadline_returns_results() -> None:
    worker = IsolatedWorker(timeout=None, policy=ExecutionPolicy(cooperative_deadline_seconds=None))
    assert worker.run("414243", ["From Hex", "To Base64"]).result == "QUJD"
    large = worker.run(
        "41" * 2_000_000, ["From Hex", "To Base64"], policy=ExecutionPolicy.unrestricted()
    )
    assert len(large.result) == 2_666_668
    assert _no_reader_threads()
