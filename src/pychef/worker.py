"""Isolated subprocess execution engine for hard memory and time bounds."""

from __future__ import annotations

import multiprocessing as mp
import pickle
import sys
from contextlib import suppress
from time import perf_counter
from typing import Any, Literal

from .errors import ExecutionLimitError, ExecutionTimeoutError, PyChefError
from .execution import ExecutionContext, ExecutionPolicy
from .types import BakeResult, Data, RecipeConfig


def _worker_entry(
    conn: Any,
    value: Data,
    config: Any,
    policy: ExecutionPolicy,
    hard_memory_limit_bytes: int | None,
    return_type: Literal["str", "bytes"] | None,
    trace: bool,
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

        context = ExecutionContext(policy=policy, trace_enabled=trace)
        recipe = Recipe(config)
        result, progress = recipe.execute(value, context=context)
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
        self._current_process: Any = None
        self._closed: bool = False

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
        hard_memory_limit_bytes: int | None = None,
        return_type: Literal["str", "bytes"] | None = None,
        trace: bool = False,
    ) -> BakeResult:
        if self._closed:
            raise RuntimeError("IsolatedWorker is closed")

        eff_hard_limit = (
            hard_memory_limit_bytes
            if hard_memory_limit_bytes is not None
            else self.hard_memory_limit_bytes
        )
        if eff_hard_limit is not None and not self.is_hard_memory_limit_supported():
            raise RuntimeError(
                f"Hard process memory limits are not supported on platform '{sys.platform}'. "
                "Use cooperative max_memory_bytes in ExecutionPolicy or run inside "
                "cgroups/containers."
            )

        eff_policy = policy or self.policy
        # Extract serializable step definitions if Recipe instance
        config = recipe.steps if hasattr(recipe, "steps") else recipe
        ctx = mp.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)

        timeout = (
            self.timeout if self.timeout is not None else eff_policy.cooperative_deadline_seconds
        )

        process = ctx.Process(
            target=_worker_entry,
            args=(child_conn, value, config, eff_policy, eff_hard_limit, return_type, trace),
        )
        self._current_process = process
        process.start()
        child_conn.close()

        payload: dict[str, Any] | None = None
        started = perf_counter()

        try:
            if timeout is not None:
                if parent_conn.poll(timeout):
                    payload = parent_conn.recv()
                else:
                    self._terminate_process(process)
                    raise ExecutionTimeoutError(
                        f"Isolated worker exceeded deadline of {timeout}s",
                    )
            else:
                payload = parent_conn.recv()

            process.join(timeout=2.0)
        except EOFError:
            process.join(timeout=1.0)
            exitcode = process.exitcode
            msg = f"Worker process terminated unexpectedly with exit code {exitcode}"
            raise ExecutionLimitError(
                "max_memory_bytes",
                f"{msg} (likely exceeded OS memory limit or was killed by system)",
            ) from None
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
            if process.is_alive():
                process.terminate()
                process.join(timeout=1.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1.0)
            else:
                process.join(timeout=0.1)
        except OSError:
            pass


def bake_isolated(
    value: Data,
    recipe: RecipeConfig | Any,
    *,
    policy: ExecutionPolicy | None = None,
    timeout: float | None = None,
    hard_memory_limit_bytes: int | None = None,
    return_type: Literal["str", "bytes"] | None = None,
) -> Data:
    """Execute *recipe* on *value* in a separate worker process."""
    worker = IsolatedWorker(
        timeout=timeout,
        policy=policy,
        hard_memory_limit_bytes=hard_memory_limit_bytes,
    )
    return worker.run(value, recipe, return_type=return_type).result
