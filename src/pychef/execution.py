"""Execution policy and per-execution context.

``ExecutionPolicy`` is a frozen, validated description of the limits that apply
to one recipe execution.  ``ExecutionContext`` is created per execution (never a
global singleton) and shared by all nested recipes (Fork, Subsection, ...), so
budgets cannot be reset by recursion.

All limits are **cooperative**: they are checked by the engine between steps
and after each operation.  They cannot interrupt an operation that is already
running (for example a catastrophic regular expression or a huge ``To Hex``).
Hard limits require process-level isolation, see ``docs/security.md``.
"""

from __future__ import annotations

import contextvars
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from .errors import ExecutionLimitError, ExecutionTimeoutError, OperationPermissionError
from .types import Data, TraceStep

#: Operations that open network connections.
NETWORK_OPERATIONS = frozenset({"HTTP request", "DNS over HTTPS"})

_TRACE_ENTRY_OVERHEAD = 192  # conservative estimate of bytes per recorded trace step


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    """Resource and permission limits for one execution.

    ``None`` disables the respective numeric limit.  The dataclass defaults are
    the *restrictive* defaults (no network); use :meth:`permissive` for the
    historical behaviour that is applied when no policy is passed at all, and
    :meth:`untrusted` for a profile suitable for untrusted recipes and data.

    ``cooperative_deadline_seconds`` is checked between steps only; it is not a
    hard timeout.
    """

    allow_network: bool = False
    max_input_bytes: int | None = None
    max_output_bytes: int | None = None
    max_steps: int | None = None
    max_recursion_depth: int | None = None
    max_branches: int | None = None
    max_trace_bytes: int | None = None
    cooperative_deadline_seconds: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allow_network, bool):
            raise TypeError("allow_network must be a bool")
        for name in (
            "max_input_bytes",
            "max_output_bytes",
            "max_steps",
            "max_recursion_depth",
            "max_branches",
            "max_trace_bytes",
        ):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be None or a non-negative integer, got {value!r}")
        deadline = self.cooperative_deadline_seconds
        if deadline is not None and (
            isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or deadline <= 0
        ):
            raise ValueError("cooperative_deadline_seconds must be None or a positive number")

    @classmethod
    def permissive(cls) -> ExecutionPolicy:
        """No numeric limits, network allowed (SSRF protection still applies)."""
        return cls(allow_network=True)

    @classmethod
    def untrusted(cls) -> ExecutionPolicy:
        """Conservative profile for untrusted recipes and inputs."""
        return cls(
            allow_network=False,
            max_input_bytes=16 * 1024 * 1024,
            max_output_bytes=64 * 1024 * 1024,
            max_steps=10_000,
            max_recursion_depth=8,
            max_branches=10_000,
            max_trace_bytes=1024 * 1024,
            cooperative_deadline_seconds=30.0,
        )


def data_size(value: Data) -> int:
    """Size in bytes; ``str`` is measured as UTF-8 so text and bytes are comparable."""
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode("utf-8", "surrogatepass"))


def _within(value: Data, limit: int) -> bool:
    if isinstance(value, bytes):
        return len(value) <= limit
    if len(value) > limit:  # UTF-8 needs at least one byte per character
        return False
    if len(value) * 4 <= limit:  # and at most four
        return True
    return data_size(value) <= limit


@dataclass(slots=True)
class ExecutionContext:
    """Mutable state shared by an execution and all nested executions."""

    policy: ExecutionPolicy = field(default_factory=ExecutionPolicy.permissive)
    trace_enabled: bool = False
    execution_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    steps: int = 0
    branches: int = 0
    depth: int = 0
    position: int = 0
    branch_path: tuple[int, ...] = ()
    trace: list[TraceStep] = field(default_factory=list)
    _trace_bytes: int = 0
    _started: float = field(default_factory=perf_counter)
    _cancelled: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def elapsed(self) -> float:
        return perf_counter() - self._started

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Request cooperative cancellation; takes effect at the next step."""
        self._cancelled.set()

    def _limit(self, limit: str, message: str, operation: str | None, step: int | None) -> Any:
        return ExecutionLimitError(
            limit,
            message,
            operation_name=operation,
            step_index=step,
            branch_path=self.branch_path,
            execution_id=self.execution_id,
        )

    def charge_step(self, operation: str, step_index: int) -> None:
        """Count one engine step (including flow control and repeated jumps)."""
        self.position = step_index
        if self._cancelled.is_set():
            raise self._limit("cancelled", "execution was cancelled", operation, step_index)
        deadline = self.policy.cooperative_deadline_seconds
        if deadline is not None and self.elapsed > deadline:
            raise ExecutionTimeoutError(
                f"cooperative deadline of {deadline}s exceeded between steps",
                operation_name=operation,
                step_index=step_index,
                branch_path=self.branch_path,
                execution_id=self.execution_id,
            )
        with self._lock:
            self.steps += 1
            exceeded = self.policy.max_steps is not None and self.steps > self.policy.max_steps
        if exceeded:
            raise self._limit(
                "max_steps",
                f"step budget of {self.policy.max_steps} exceeded",
                operation,
                step_index,
            )

    def charge_branch(self, operation: str, step_index: int) -> None:
        with self._lock:
            self.branches += 1
            exceeded = (
                self.policy.max_branches is not None and self.branches > self.policy.max_branches
            )
        if exceeded:
            raise self._limit(
                "max_branches",
                f"branch budget of {self.policy.max_branches} exceeded",
                operation,
                step_index,
            )

    @contextmanager
    def nested(self, operation: str, step_index: int) -> Iterator[None]:
        """Enter a nested recipe; depth is restored on exit, counters are not."""
        limit = self.policy.max_recursion_depth
        if limit is not None and self.depth + 1 > limit:
            raise self._limit(
                "max_recursion_depth",
                f"recursion depth limit of {limit} exceeded",
                operation,
                step_index,
            )
        saved_path = self.branch_path
        self.depth += 1
        self.branch_path = (*saved_path, step_index)
        try:
            yield
        finally:
            self.depth -= 1
            self.branch_path = saved_path

    def check_input(
        self, value: Data, operation: str | None = None, step: int | None = None
    ) -> None:
        limit = self.policy.max_input_bytes
        if limit is not None and not _within(value, limit):
            raise self._limit("max_input_bytes", f"input exceeds {limit} bytes", operation, step)

    def check_output(
        self, value: Data, operation: str | None = None, step: int | None = None
    ) -> None:
        limit = self.policy.max_output_bytes
        if limit is not None and not _within(value, limit):
            raise self._limit("max_output_bytes", f"output exceeds {limit} bytes", operation, step)

    def require_operation(self, operation: str, step_index: int) -> None:
        if operation in NETWORK_OPERATIONS and not self.policy.allow_network:
            raise OperationPermissionError(
                operation,
                "network access is not permitted by the execution policy",
                step_index=step_index,
                branch_path=self.branch_path,
                execution_id=self.execution_id,
            )

    def record(
        self,
        operation: str,
        step_index: int,
        before: Data,
        after: Data | None,
        started: float,
        error: BaseException | None,
    ) -> None:
        if not self.trace_enabled:
            return
        cost = _TRACE_ENTRY_OVERHEAD + len(operation)
        limit = self.policy.max_trace_bytes
        with self._lock:
            if limit is not None and self._trace_bytes + cost > limit:
                raise self._limit(
                    "max_trace_bytes", f"trace exceeds {limit} bytes", operation, step_index
                )
            self._trace_bytes += cost
            self.trace.append(
                TraceStep(
                    operation=operation,
                    step_index=step_index,
                    branch_path=self.branch_path,
                    input_type="bytes" if isinstance(before, bytes) else "string",
                    output_type=(
                        "none"
                        if after is None
                        else "bytes"
                        if isinstance(after, bytes)
                        else "string"
                    ),
                    input_size=data_size(before),
                    output_size=0 if after is None else data_size(after),
                    duration_ms=(perf_counter() - started) * 1000,
                    error=type(error).__name__ if error is not None else None,
                )
            )


# Scoped (not global) holder so operation implementations, which only receive
# ``(value, args)``, can honour the policy of the execution that invoked them.
_active_policy: contextvars.ContextVar[ExecutionPolicy | None] = contextvars.ContextVar(
    "pychef_active_policy", default=None
)


@contextmanager
def active_policy(policy: ExecutionPolicy) -> Iterator[None]:
    token = _active_policy.set(policy)
    try:
        yield
    finally:
        _active_policy.reset(token)


def current_policy() -> ExecutionPolicy | None:
    """Policy of the running execution, or ``None`` outside of one (legacy direct calls)."""
    return _active_policy.get()
