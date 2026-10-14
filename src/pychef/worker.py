"""Isolated subprocess execution engine for hard memory and time bounds."""

from __future__ import annotations

import multiprocessing as mp
import pickle
import sys
import threading
from collections.abc import Callable
from contextlib import suppress
from time import perf_counter
from typing import TYPE_CHECKING, Any, Literal, cast

from .errors import ExecutionLimitError, ExecutionTimeoutError, PyChefError
from .execution import ExecutionContext, ExecutionPolicy
from .types import BakeResult, Data, RecipeConfig

if TYPE_CHECKING:
    from .registry import OperationRegistry

_UNSET: Any = object()


def _worker_entry(
    conn: Any,
    value: Data,
    config: Any,
    policy: ExecutionPolicy,
    hard_memory_limit_bytes: int | None,
    return_type: Literal["str", "bytes"] | None,
    trace: bool,
    registry: Any = None,
) -> None:
    """Entry point executed in an isolated child process."""
    try:
        # Apply OS-level hard memory limit if configured and supported
        if hard_memory_limit_bytes is not None:
            try:
                import resource

                if hasattr(resource, "RLIMIT_AS"):
                    resource.setrlimit(
                        resource.RLIMIT_AS, (hard_memory_limit_bytes, hard_memory_limit_bytes)
                    )
                elif hasattr(resource, "RLIMIT_DATA"):
                    resource.setrlimit(
                        resource.RLIMIT_DATA, (hard_memory_limit_bytes, hard_memory_limit_bytes)
                    )
            except (ImportError, ValueError, OSError) as exc:
                raise RuntimeError(f"Failed to enforce OS hard memory limit: {exc}") from exc

        from .recipe import Recipe, _convert_result
        from .registry import registry as default_registry

        eff_registry = registry if registry is not None else default_registry
        context = ExecutionContext(policy=policy, trace_enabled=trace)
        recipe = Recipe(config)
        result, progress = recipe.execute(value, operation_registry=eff_registry, context=context)
        converted = _convert_result(result, return_type)
        conn.send(
            {
                "success": True,
                "result": converted,
                "type": "bytes" if isinstance(converted, bytes) else "string",
                "progress": progress,
                "trace": tuple(context.trace),
                "execution_id": context.execution_id,
            }
        )
    except BaseException as exc:
        exec_id = getattr(context, "execution_id", None) if "context" in locals() else None
        err_payload: Any = exc
        try:
            pickle.dumps(exc)
        except Exception:
            err_payload = {
                "__unpicklable__": True,
                "type": type(exc).__name__,
                "module": type(exc).__module__,
                "message": str(exc),
            }
        with suppress(OSError):
            conn.send(
                {
                    "success": False,
                    "error": err_payload,
                    "execution_id": exec_id,
                }
            )
    finally:
        with suppress(OSError):
            conn.close()


def _recv_before_deadline(
    conn: Any, timeout: float, on_timeout: Callable[[], None] | None = None
) -> Any:
    """Receive one complete message or raise :class:`TimeoutError`.

    ``Connection.poll()`` only reports that *some* bytes are readable; a
    following ``recv()`` blocks until the entire message has arrived, so a child
    that stalls mid-message would defeat the deadline. The blocking read runs in
    a helper thread. At the deadline *on_timeout* (which must stop the child) is
    called and the thread is joined before :class:`TimeoutError` is raised, so
    the caller never closes a descriptor that a reader thread still uses.
    """
    outcome: dict[str, Any] = {}

    def read() -> None:
        try:
            outcome["payload"] = conn.recv()
        except BaseException as exc:
            outcome["error"] = exc

    reader = threading.Thread(target=read, name="pychef-worker-recv", daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive():
        if on_timeout is not None:
            on_timeout()
        reader.join(5.0)
        raise TimeoutError
    if "error" in outcome:
        raise outcome["error"]
    return outcome["payload"]


def _receive_payload(
    conn: Any, timeout: float | None, on_timeout: Callable[[], None] | None
) -> dict[str, Any]:
    """Receive and validate the child's result message.

    Pipe failures surface as :class:`EOFError` (handled by the caller as an
    unexpected child exit); undecodable or malformed messages become a
    :class:`PyChefError` instead of leaking pickle internals.
    """
    try:
        payload = (
            conn.recv() if timeout is None else _recv_before_deadline(conn, timeout, on_timeout)
        )
    except (EOFError, TimeoutError):
        raise
    except OSError as exc:
        raise EOFError(str(exc)) from exc
    except Exception:
        raise PyChefError("Isolated worker returned an unreadable result message") from None
    if not isinstance(payload, dict) or "success" not in payload:
        raise PyChefError("Isolated worker returned a malformed result message")
    return payload


class IsolatedWorker:
    """Execute recipes inside an isolated process with hard OS and deadline limits.

    Ensures that catastrophic regexes, unbounded loops, or memory spikes cannot
    destabilize or crash the parent application process.
    """

    def __init__(
        self,
        *,
        timeout: float | None = None,
        policy: ExecutionPolicy | None = None,
        hard_memory_limit_bytes: int | None = None,
        operation_registry: OperationRegistry | None = None,
    ) -> None:
        if hard_memory_limit_bytes is not None:
            if not self.is_hard_memory_limit_supported():
                raise RuntimeError(
                    f"Hard process memory limits are not supported on platform '{sys.platform}'. "
                    "Use cooperative max_memory_bytes in ExecutionPolicy or run inside "
                    "cgroups/containers."
                )
            if not isinstance(hard_memory_limit_bytes, int) or hard_memory_limit_bytes <= 0:
                raise ValueError("hard_memory_limit_bytes must be a positive integer")
        self.timeout = timeout
        self.policy = policy or ExecutionPolicy.safe()
        self.hard_memory_limit_bytes = hard_memory_limit_bytes
        self.registry = operation_registry
        self._current_process: Any = None
        self._closed: bool = False
        self._lock = threading.Lock()

    @classmethod
    def is_hard_memory_limit_supported(cls) -> bool:
        """Return True if the current operating system supports enforcing RLIMIT_AS/DATA."""
        if not sys.platform.startswith("linux"):
            return False
        try:
            import resource

            return hasattr(resource, "RLIMIT_AS") or hasattr(resource, "RLIMIT_DATA")
        except ImportError:
            return False

    def __enter__(self) -> IsolatedWorker:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Release worker resources and terminate running processes."""
        self._closed = True
        if self._current_process is not None:
            self._terminate_process(self._current_process)
            self._current_process = None

    def run(
        self,
        value: Data,
        recipe: RecipeConfig | Any,
        *,
        policy: ExecutionPolicy | None = None,
        hard_memory_limit_bytes: int | object | None = _UNSET,
        return_type: Literal["str", "bytes"] | None = None,
        trace: bool = False,
        operation_registry: OperationRegistry | None = None,
    ) -> BakeResult:
        if self._closed:
            raise RuntimeError("IsolatedWorker is closed")

        if not self._lock.acquire(blocking=False):
            raise RuntimeError(
                "IsolatedWorker instance does not support concurrent execution. "
                "Use separate IsolatedWorker instances per thread."
            )
        try:
            return self._run_internal(
                value,
                recipe,
                policy=policy,
                hard_memory_limit_bytes=hard_memory_limit_bytes,
                return_type=return_type,
                trace=trace,
                operation_registry=operation_registry,
            )
        finally:
            self._lock.release()

    def _run_internal(
        self,
        value: Data,
        recipe: RecipeConfig | Any,
        *,
        policy: ExecutionPolicy | None = None,
        hard_memory_limit_bytes: int | object | None = _UNSET,
        return_type: Literal["str", "bytes"] | None = None,
        trace: bool = False,
        operation_registry: OperationRegistry | None = None,
    ) -> BakeResult:
        if hard_memory_limit_bytes is _UNSET:
            eff_hard_limit = self.hard_memory_limit_bytes
        else:
            eff_hard_limit = cast("int | None", hard_memory_limit_bytes)

        if eff_hard_limit is not None:
            if (
                isinstance(eff_hard_limit, bool)
                or not isinstance(eff_hard_limit, int)
                or eff_hard_limit <= 0
            ):
                raise ValueError("hard_memory_limit_bytes must be a positive integer")
            if not self.is_hard_memory_limit_supported():
                raise RuntimeError(
                    f"Hard process memory limits are not supported on platform '{sys.platform}'. "
                    "Use cooperative max_memory_bytes in ExecutionPolicy or run inside "
                    "cgroups/containers."
                )

        eff_policy = policy or self.policy
        eff_registry = operation_registry or self.registry
        # Extract serializable step definitions if Recipe instance
        config = recipe.steps if hasattr(recipe, "steps") else recipe
        ctx = mp.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)

        timeout = (
            self.timeout if self.timeout is not None else eff_policy.cooperative_deadline_seconds
        )

        started = perf_counter()
        process = ctx.Process(
            target=_worker_entry,
            args=(
                child_conn,
                value,
                config,
                eff_policy,
                eff_hard_limit,
                return_type,
                trace,
                eff_registry,
            ),
        )
        self._current_process = process
        try:
            process.start()
        except Exception:
            with suppress(OSError):
                child_conn.close()
                parent_conn.close()
            self._terminate_process(process)
            self._current_process = None
            raise

        child_conn.close()

        payload: dict[str, Any] | None = None

        try:
            if timeout is not None:
                remaining = max(0.0, timeout - (perf_counter() - started))
                try:
                    payload = _receive_payload(
                        parent_conn, remaining, lambda: self._terminate_process(process)
                    )
                except TimeoutError:
                    self._terminate_process(process)
                    raise ExecutionTimeoutError(
                        f"Isolated worker exceeded deadline of {timeout}s",
                    ) from None
            else:
                payload = _receive_payload(parent_conn, None, None)

            join_timeout = (
                max(0.1, min(2.0, timeout - (perf_counter() - started)))
                if timeout is not None
                else 2.0
            )
            process.join(timeout=join_timeout)
        except EOFError:
            process.join(timeout=1.0)
            exitcode = process.exitcode
            msg = f"Worker process terminated unexpectedly with exit code {exitcode}"
            if eff_hard_limit is not None and exitcode in (-9, 137):
                raise ExecutionLimitError(
                    "max_memory_bytes",
                    f"{msg} (likely exceeded OS memory limit or was killed by system)",
                ) from None
            raise PyChefError(msg) from None
        finally:
            with suppress(OSError):
                parent_conn.close()
            self._terminate_process(process)
            self._current_process = None

        duration_ms = (perf_counter() - started) * 1000

        if payload is None:
            raise PyChefError("Isolated worker returned no payload")

        if payload["success"]:
            return BakeResult(
                result=payload["result"],
                type=payload["type"],
                progress=payload["progress"],
                duration_ms=duration_ms,
                trace=payload.get("trace", ()),
            )
        else:
            err = payload["error"]
            if isinstance(err, dict) and err.get("__unpicklable__"):
                err_type = err.get("type", "Exception")
                err_module = err.get("module", "builtins")
                err_msg = err.get("message", "Unknown worker error")
                raise PyChefError(f"Worker raised {err_module}.{err_type}: {err_msg}")
            if isinstance(err, BaseException):
                raise err
            raise PyChefError(str(err))

    @staticmethod
    def _terminate_process(process: Any) -> None:
        """Safely ensure child process is stopped and reaped without zombies."""
        try:
            if getattr(process, "_popen", None) is not None:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=1.0)
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=1.0)
                else:
                    process.join(timeout=0.1)
        except (OSError, AssertionError):
            pass


def bake_isolated(
    value: Data,
    recipe: RecipeConfig | Any,
    *,
    policy: ExecutionPolicy | None = None,
    timeout: float | None = None,
    hard_memory_limit_bytes: int | None = None,
    return_type: Literal["str", "bytes"] | None = None,
    operation_registry: OperationRegistry | None = None,
) -> Data:
    """Execute *recipe* on *value* in a separate worker process."""
    worker = IsolatedWorker(
        timeout=timeout,
        policy=policy,
        hard_memory_limit_bytes=hard_memory_limit_bytes,
        operation_registry=operation_registry,
    )
    return worker.run(
        value,
        recipe,
        return_type=return_type,
        operation_registry=operation_registry,
    ).result
