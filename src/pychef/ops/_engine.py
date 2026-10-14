"""Policy-aware execution of single operations for :mod:`pychef.ops`.

Every direct call is run through :class:`pychef.recipe.Recipe`, the same engine
used by ``bake()``, ``Chef`` and ``Pipeline``. Limits, network permissions and
error handling are therefore identical regardless of the entry point.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from ..execution import ExecutionPolicy, active_policy, current_policy
from ..recipe import Recipe
from ..registry import OperationRegistry, registry
from ..types import Data, RecipeStep

BytesLike = bytes | bytearray | memoryview


def effective_policy(policy: ExecutionPolicy | None = None) -> ExecutionPolicy:
    """Resolve the policy for a direct call.

    Precedence: explicit *policy*, then the innermost active policy (set by
    :func:`using_policy` or by a running ``bake``/``Pipeline``/``Chef`` execution,
    for example when a helper is called from a ``Pipeline.apply`` callable), then
    :meth:`ExecutionPolicy.safe`.
    """
    return policy or current_policy() or ExecutionPolicy.safe()


@contextmanager
def using_policy(policy: ExecutionPolicy) -> Iterator[None]:
    """Use *policy* for every :mod:`pychef.ops` call made inside the ``with`` block.

    This sets the same scoped (:mod:`contextvars`) policy that executions use, so it
    is local to the current thread or asyncio task, nests innermost-wins with running
    executions, and never changes process-wide state.
    """
    if not isinstance(policy, ExecutionPolicy):
        raise TypeError("policy must be an ExecutionPolicy")
    with active_policy(policy):
        yield


def coerce_input(value: Any) -> Data:
    """Accept ``str`` and bytes-like input; reject everything else explicitly."""
    if isinstance(value, (str, bytes)):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"expected str or bytes-like input, not {type(value).__name__}")


def run_operation(
    name: str,
    value: str | BytesLike,
    args: Sequence[Any] = (),
    *,
    policy: ExecutionPolicy | None = None,
    operation_registry: OperationRegistry = registry,
) -> Data:
    """Run any registered operation once and return its raw result.

    *args* are the positional CyberChef operation arguments, exactly as in a
    recipe step (``{"op": name, "args": [...]}``). The input *value*, the
    operation *args* and the engine *policy* are separate parameters and never
    overlap. The result is ``str`` or ``bytes``, depending on the operation.

    The default policy is described in :func:`effective_policy`.
    """
    if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
        raise TypeError("args must be a list or tuple of operation arguments")
    step = RecipeStep(name, tuple(args))
    result, _ = Recipe([step]).execute(
        coerce_input(value),
        operation_registry=operation_registry,
        policy=effective_policy(policy),
    )
    return result


def as_bytes(result: Data) -> bytes:
    """Narrow an operation result to ``bytes`` (operations may return either type)."""
    return result if isinstance(result, bytes) else result.encode("utf-8")


def as_text(result: Data) -> str:
    return result if isinstance(result, str) else result.decode("utf-8")


def guard_input(value: Any, policy: ExecutionPolicy | None = None) -> Data:
    """Validate type and apply the policy's input limits for pure-Python helpers."""
    from ..execution import ExecutionContext

    data = coerce_input(value)
    ExecutionContext(policy=effective_policy(policy)).check_input(data)
    return data
