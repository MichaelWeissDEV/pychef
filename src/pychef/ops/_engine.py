"""Policy-aware execution of single operations for :mod:`pychef.ops`.

Every direct call is run through :class:`pychef.recipe.Recipe`, the same engine
used by ``bake()``, ``Chef`` and ``Pipeline``. Limits, network permissions and
error handling are therefore identical regardless of the entry point.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from time import perf_counter
from typing import Any, TypeVar

from ..execution import (
    ExecutionContext,
    ExecutionPolicy,
    active_context,
    active_policy,
    current_context,
    current_policy,
    resolve_context,
)
from ..recipe import Recipe
from ..registry import OperationRegistry, registry
from ..types import Data, RecipeStep

T = TypeVar("T")
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
    running = current_context()
    if running is not None and policy != running.policy:
        raise ValueError(
            "using_policy() cannot change the policy inside a running execution "
            "(for example inside Pipeline.apply); nested calls inherit it"
        )
    with active_policy(policy):
        yield


def direct_context(policy: ExecutionPolicy | None = None) -> ExecutionContext:
    """Context for a direct call: the running one when nested, else a fresh one.

    Independent top-level calls each get their own context (and budgets); calls
    made while an execution is running share that execution's context.
    """
    if current_context() is not None:
        return resolve_context(policy)
    return ExecutionContext(policy=effective_policy(policy))


def execute_direct(
    name: str,
    value: Data,
    function: Callable[[Data], T],
    *,
    policy: ExecutionPolicy | None = None,
) -> T:
    """Run a pure-Python *function* under the shared execution rules.

    Validates the input, charges one step to the (shared) context, checks the
    operation permission, and applies output limits and tracing, so helpers that do
    not go through the registry obey the same resource model as registry operations.
    Exceptions raised by *function* propagate unchanged.
    """
    context = direct_context(policy)
    with active_context(context):
        index = context.position
        context.check_input(value, name, index)
        context.charge_step(name, index)
        context.require_operation(name, index)
        started = perf_counter()
        try:
            result = function(value)
        except Exception as error:
            context.record(name, index, value, None, started, error)
            raise
        if isinstance(result, (str, bytes)):
            context.check_output(result, name, index)
            context.record(name, index, value, result, started, None)
        return result


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
        context=direct_context(policy),
    )
    return result


def as_bytes(result: Data) -> bytes:
    """Narrow an operation result to ``bytes`` (operations may return either type)."""
    return result if isinstance(result, bytes) else result.encode("utf-8")


def as_text(result: Data) -> str:
    return result if isinstance(result, str) else result.decode("utf-8")
