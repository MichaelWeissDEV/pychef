"""CyberChef-compatible recipe parsing and execution."""

from __future__ import annotations

from collections.abc import Mapping
from time import perf_counter
from typing import Any, Literal

from .errors import OperationError, RecipeError
from .registry import OperationRegistry, registry
from .types import BakeResult, Data, RecipeConfig, RecipeStep, to_bytes, to_text


class Recipe:
    """A validated sequence of data transformation operations."""

    def __init__(self, config: RecipeConfig) -> None:
        self.steps = tuple(self._parse_step(step) for step in config)

    @staticmethod
    def _parse_step(step: RecipeStep | Mapping[str, Any] | str) -> RecipeStep:
        if isinstance(step, RecipeStep):
            return step
        if isinstance(step, str):
            return RecipeStep(step)
        if not isinstance(step, Mapping):
            raise RecipeError(f"recipe step must be a string, mapping, or RecipeStep: {step!r}")
        name = step.get("op")
        if not isinstance(name, str) or not name:
            raise RecipeError(f"recipe step has no valid 'op': {step!r}")
        args = step.get("args", ())
        if args is None:
            args = ()
        if isinstance(args, (str, bytes)) or not isinstance(args, (list, tuple)):
            raise RecipeError(f"arguments for {name!r} must be a list or tuple")
        return RecipeStep(
            op=name,
            args=tuple(args),
            disabled=bool(step.get("disabled", False)),
            breakpoint=bool(step.get("breakpoint", False)),
        )

    def execute(
        self,
        value: Data,
        *,
        operation_registry: OperationRegistry = registry,
    ) -> tuple[Data, int]:
        progress = 0
        for index, step in enumerate(self.steps):
            if step.breakpoint:
                break
            if step.disabled or step.op == "Comment":
                progress = index + 1
                continue
            if step.op == "Return":
                progress = index + 1
                break
            implementation = operation_registry.get(step.op)
            try:
                value = implementation.run(value, step.args)
            except OperationError:
                raise
            except Exception as exc:
                raise OperationError(step.op, str(exc)) from exc
            progress = index + 1
        return value, progress


class Chef:
    """Execute recipes with a small, synchronous Python API."""

    def __init__(self, *, operation_registry: OperationRegistry = registry) -> None:
        self.registry = operation_registry

    def bake_result(
        self,
        value: Data,
        recipe: RecipeConfig | Recipe,
        *,
        return_type: Literal["str", "bytes"] | None = None,
        raise_errors: bool = True,
    ) -> BakeResult:
        parsed = recipe if isinstance(recipe, Recipe) else Recipe(recipe)
        started = perf_counter()
        progress = 0
        error: Exception | None = None
        result: Data = value
        try:
            result, progress = parsed.execute(value, operation_registry=self.registry)
            result = _convert_result(result, return_type)
        except Exception as exc:
            if raise_errors:
                raise
            error = exc
        duration_ms = (perf_counter() - started) * 1000
        return BakeResult(
            result=result,
            type="bytes" if isinstance(result, bytes) else "string",
            progress=progress,
            duration_ms=duration_ms,
            error=error,
        )

    def bake(
        self,
        value: Data,
        recipe: RecipeConfig | Recipe,
        *,
        return_type: Literal["str", "bytes"] | None = None,
    ) -> Data:
        return self.bake_result(value, recipe, return_type=return_type).result


def _convert_result(value: Data, return_type: Literal["str", "bytes"] | None) -> Data:
    if return_type == "str":
        return to_text(value)
    if return_type == "bytes":
        return to_bytes(value)
    return value


def bake(
    value: Data,
    recipe: RecipeConfig | Recipe,
    *,
    return_type: Literal["str", "bytes"] | None = None,
) -> Data:
    """Bake *value* with *recipe* and return the transformed value."""
    return Chef().bake(value, recipe, return_type=return_type)
