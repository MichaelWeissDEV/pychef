"""CyberChef-compatible recipe parsing and execution."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import replace
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
        steps = list(self.steps)
        progress = 0
        index = 0
        jump_counts: dict[int, int] = {}
        while index < len(steps):
            step = steps[index]
            if step.breakpoint:
                break
            if step.disabled or step.op == "Comment":
                progress = index + 1
                index += 1
                continue
            if step.op == "Return":
                progress = index + 1
                break
            if step.op in {"Jump", "Conditional Jump"}:
                should_jump = step.op == "Jump"
                if step.op == "Conditional Jump":
                    pattern = str(step.args[0] if step.args else "")
                    invert = bool(step.args[1] if len(step.args) > 1 else False)
                    matched = bool(pattern and re.search(pattern, to_text(value)))
                    should_jump = matched != invert
                    label = str(step.args[2] if len(step.args) > 2 else "")
                    maximum = int(step.args[3] if len(step.args) > 3 else 10)
                else:
                    label = str(step.args[0] if step.args else "")
                    maximum = int(step.args[1] if len(step.args) > 1 else 10)
                target = next(
                    (
                        position
                        for position, candidate in enumerate(steps)
                        if candidate.op == "Label"
                        and candidate.args
                        and str(candidate.args[0]) == label
                    ),
                    -1,
                )
                count = jump_counts.get(index, 0)
                if should_jump and target >= 0 and (target > index or count < maximum):
                    jump_counts[index] = count + 1
                    index = target
                    progress = index
                    continue
                jump_counts[index] = 0
                progress = index + 1
                index += 1
                continue
            if step.op == "Register":
                pattern = str(step.args[0] if step.args else r"([\s\S]*)")
                flags = (re.IGNORECASE if len(step.args) < 2 or step.args[1] else 0)
                flags |= re.MULTILINE if len(step.args) > 2 and step.args[2] else 0
                flags |= re.DOTALL if len(step.args) > 3 and step.args[3] else 0
                match = re.search(pattern, to_text(value), flags)
                if match:
                    registers = match.groups()
                    for position in range(index + 1, len(steps)):
                        new_args = tuple(
                            _replace_registers(argument, registers) for argument in steps[position].args
                        )
                        steps[position] = replace(steps[position], args=new_args)
                progress = index + 1
                index += 1
                continue
            if step.op in {"Fork", "Subsection"}:
                merge_index = _matching_merge(steps, index)
                substeps = steps[index + 1 : merge_index]
                ignore_errors = bool(step.args[2 if step.op == "Fork" else 3]) if len(step.args) > (2 if step.op == "Fork" else 3) else False
                if step.op == "Fork":
                    split_delimiter = _binary_delimiter(str(step.args[0] if step.args else "\n"))
                    merge_delimiter = _binary_delimiter(str(step.args[1] if len(step.args) > 1 else "\n"))
                    outputs = []
                    for part in to_text(value).split(split_delimiter) if value else []:
                        try:
                            outputs.append(Recipe(substeps).execute(part, operation_registry=operation_registry)[0])
                        except Exception:
                            if not ignore_errors:
                                raise
                            outputs.append(part)
                    value = merge_delimiter.join(to_text(item) for item in outputs)
                else:
                    pattern = str(step.args[0] if step.args else "")
                    flags = 0 if len(step.args) < 2 or step.args[1] else re.IGNORECASE
                    global_matching = bool(step.args[2] if len(step.args) > 2 else True)
                    source = to_text(value)
                    matches = list(re.finditer(pattern, source, flags)) if pattern else []
                    if not global_matching:
                        matches = matches[:1]
                    output = []
                    cursor = 0
                    for match in matches:
                        selected = match.group(1) if match.groups() else match.group(0)
                        start, end = match.span(1) if match.groups() else match.span(0)
                        output.append(source[cursor:start])
                        try:
                            transformed = Recipe(copy.deepcopy(substeps)).execute(
                                selected, operation_registry=operation_registry
                            )[0]
                        except Exception:
                            if not ignore_errors:
                                raise
                            transformed = selected
                        output.append(to_text(transformed))
                        cursor = end
                    output.append(source[cursor:])
                    value = "".join(output)
                progress = merge_index + 1
                index = merge_index + 1
                continue
            if step.op == "Merge":
                progress = index + 1
                index += 1
                continue
            implementation = operation_registry.get(step.op)
            try:
                value = implementation.run(value, step.args)
            except OperationError:
                raise
            except Exception as exc:
                raise OperationError(step.op, str(exc)) from exc
            progress = index + 1
            index += 1
        return value, progress


def _binary_delimiter(value: str) -> str:
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return value


def _matching_merge(steps: list[RecipeStep], start: int) -> int:
    depth = 1
    for position in range(start + 1, len(steps)):
        step = steps[position]
        if step.disabled:
            continue
        if step.op in {"Fork", "Subsection"}:
            depth += 1
        elif step.op == "Merge":
            if step.args and step.args[0]:
                return position
            depth -= 1
            if depth == 0:
                return position
    return len(steps)


def _replace_registers(value: Any, registers: tuple[str | None, ...]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_registers(item, registers) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_registers(item, registers) for item in value]
    if not isinstance(value, str):
        return value

    def replacement(match: re.Match[str]) -> str:
        slashes, number = match.groups()
        if len(slashes) % 2:
            return match.group(0)[1:]
        index = int(number)
        if index >= len(registers):
            return match.group(0)
        return slashes + (registers[index] or "")

    return re.sub(r"(\\*)\$R(\d{1,2})", replacement, value)


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
