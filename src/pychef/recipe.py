"""CyberChef-compatible recipe parsing and execution."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import replace
from time import perf_counter
from typing import Any, Literal

from .errors import (
    ExecutionLimitError,
    InvalidOperationArgumentsError,
    OperationError,
    OperationPermissionError,
    RecipeError,
)
from .execution import ExecutionContext, ExecutionPolicy, active_policy
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
        policy: ExecutionPolicy | None = None,
        context: ExecutionContext | None = None,
    ) -> tuple[Data, int]:
        """Run the recipe and return ``(value, progress)``.

        Without *policy* or *context* the historical, unlimited behaviour
        (:meth:`ExecutionPolicy.permissive`) applies.  A *context* may be shared
        to account several executions against one budget.
        """
        if context is None:
            context = ExecutionContext(policy=policy or ExecutionPolicy.permissive())
        elif policy is not None and policy is not context.policy:
            raise ValueError("pass either policy or context, not both")
        with active_policy(context.policy):
            context.check_input(value)
            result, progress = self._run(value, operation_registry, context)
            context.check_output(result)
            return result, progress

    def _run(
        self,
        value: Data,
        operation_registry: OperationRegistry,
        ctx: ExecutionContext,
        base: int = 0,
    ) -> tuple[Data, int]:
        steps = list(self.steps)
        progress = 0
        index = 0
        jump_counts: dict[int, int] = {}
        while index < len(steps):
            step = steps[index]
            abs_index = base + index  # absolute index for diagnostics
            if step.breakpoint:
                break
            ctx.charge_step(step.op, abs_index)
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
                    matched = bool(
                        pattern and _search(pattern, to_text(value), 0, step.op, abs_index, ctx)
                    )
                    should_jump = bool(pattern) and matched != invert
                    label = str(step.args[2] if len(step.args) > 2 else "")
                    maximum = _jump_limit(step, 3, abs_index, ctx)
                else:
                    label = str(step.args[0] if step.args else "")
                    maximum = _jump_limit(step, 1, abs_index, ctx)
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
                flags = re.IGNORECASE if len(step.args) < 2 or step.args[1] else 0
                flags |= re.MULTILINE if len(step.args) > 2 and step.args[2] else 0
                flags |= re.DOTALL if len(step.args) > 3 and step.args[3] else 0
                match = _search(pattern, to_text(value), flags, step.op, abs_index, ctx)
                if match:
                    registers = match.groups()
                    for position in range(index + 1, len(steps)):
                        new_args = tuple(
                            _replace_registers(argument, registers)
                            for argument in steps[position].args
                        )
                        steps[position] = replace(steps[position], args=new_args)
                progress = index + 1
                index += 1
                continue
            if step.op in {"Fork", "Subsection"}:
                merge_index = _matching_merge(steps, index)
                substeps = steps[index + 1 : merge_index]
                ignore_errors = (
                    bool(step.args[2 if step.op == "Fork" else 3])
                    if len(step.args) > (2 if step.op == "Fork" else 3)
                    else False
                )
                if step.op == "Fork":
                    split_delimiter = _binary_delimiter(str(step.args[0] if step.args else "\n"))
                    merge_delimiter = _binary_delimiter(
                        str(step.args[1] if len(step.args) > 1 else "\n")
                    )
                    outputs = []
                    text = to_text(value)
                    # JavaScript's split("") yields single characters; str.split("") raises.
                    parts = (
                        ([] if not value else list(text))
                        if split_delimiter == ""
                        else (text.split(split_delimiter) if value else [])
                    )
                    for part in parts:
                        ctx.charge_branch(step.op, abs_index)
                        try:
                            with ctx.nested(step.op, abs_index):
                                outputs.append(
                                    Recipe(substeps)._run(
                                        part, operation_registry, ctx, base + index + 1
                                    )[0]
                                )
                        except _FATAL_ERRORS:
                            raise
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
                    matches = (
                        _finditer(pattern, source, flags, step.op, abs_index, ctx)
                        if pattern
                        else []
                    )
                    if not global_matching:
                        matches = matches[:1]
                    output = []
                    cursor = 0
                    for match in matches:
                        selected = match.group(1) if match.groups() else match.group(0)
                        start, end = match.span(1) if match.groups() else match.span(0)
                        output.append(source[cursor:start])
                        ctx.charge_branch(step.op, abs_index)
                        try:
                            with ctx.nested(step.op, abs_index):
                                transformed = Recipe(substeps)._run(
                                    selected, operation_registry, ctx, base + index + 1
                                )[0]
                        except _FATAL_ERRORS:
                            raise
                        except Exception:
                            if not ignore_errors:
                                raise
                            transformed = selected
                        output.append(to_text(transformed))
                        cursor = end
                    output.append(source[cursor:])
                    value = "".join(output)
                ctx.check_output(value, step.op, abs_index)
                progress = merge_index + 1
                index = merge_index + 1
                continue
            if step.op == "Merge":
                progress = index + 1
                index += 1
                continue
            ctx.require_operation(step.op, abs_index)
            implementation = operation_registry.get(step.op)
            started = perf_counter()
            before = value
            try:
                value = implementation.run(value, step.args)
            except OperationError as exc:
                if exc.step_index is None:
                    exc.step_index = abs_index
                    exc.branch_path = ctx.branch_path
                    exc.execution_id = ctx.execution_id
                ctx.record(step.op, abs_index, before, None, started, exc)
                raise
            except Exception as exc:
                error = OperationError(
                    step.op,
                    str(exc),
                    step_index=abs_index,
                    branch_path=ctx.branch_path,
                    execution_id=ctx.execution_id,
                )
                ctx.record(step.op, abs_index, before, None, started, exc)
                raise error from exc
            ctx.record(step.op, abs_index, before, value, started, None)
            ctx.check_output(value, step.op, abs_index)
            progress = index + 1
            index += 1
        return value, progress


_FATAL_ERRORS = (ExecutionLimitError, OperationPermissionError)

_ESCAPES = re.compile(
    r"\\(?:([abfnrtv'\"\\])|([0-3][0-7]{2}|[0-7]{1,2})|x([0-9a-fA-F]{2})"
    r"|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\})"
)
_SIMPLE_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "'": "'",
    '"': '"',
    "\\": "\\",
}


def _binary_delimiter(value: str) -> str:
    """Interpret backslash escapes like CyberChef's ``Utils.parseEscapedChars``.

    Only recognised escape sequences are replaced; every other character
    (including non-ASCII text, lone backslashes and invalid escapes) is kept.
    """

    def replace_escape(match: re.Match[str]) -> str:
        simple, octal, hexadecimal, unicode4, unicode_braced = match.groups()
        if simple:
            return _SIMPLE_ESCAPES[simple]
        if octal:
            return chr(int(octal, 8))
        code = int(hexadecimal or unicode4 or unicode_braced, 16)
        return chr(code) if code <= 0x10FFFF else match.group(0)

    return _ESCAPES.sub(replace_escape, value)


def _compile(
    pattern: str, flags: int, operation: str, index: int, ctx: ExecutionContext
) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise InvalidOperationArgumentsError(
            operation,
            f"invalid regular expression: {exc}",
            step_index=index,
            branch_path=ctx.branch_path,
            execution_id=ctx.execution_id,
        ) from exc


def _search(
    pattern: str, text: str, flags: int, operation: str, index: int, ctx: ExecutionContext
) -> re.Match[str] | None:
    return _compile(pattern, flags, operation, index, ctx).search(text)


def _finditer(
    pattern: str, text: str, flags: int, operation: str, index: int, ctx: ExecutionContext
) -> list[re.Match[str]]:
    return list(_compile(pattern, flags, operation, index, ctx).finditer(text))


def _jump_limit(step: RecipeStep, position: int, index: int, ctx: ExecutionContext) -> int:
    raw = step.args[position] if len(step.args) > position else 10
    try:
        if isinstance(raw, bool):
            raise ValueError("boolean")
        maximum = int(raw)
    except (TypeError, ValueError) as exc:
        raise InvalidOperationArgumentsError(
            step.op,
            "maximum jumps must be an integer",
            step_index=index,
            branch_path=ctx.branch_path,
            execution_id=ctx.execution_id,
        ) from exc
    if maximum < 0:
        raise InvalidOperationArgumentsError(
            step.op,
            "maximum jumps must not be negative",
            step_index=index,
            branch_path=ctx.branch_path,
            execution_id=ctx.execution_id,
        )
    return maximum


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

    def __init__(
        self,
        *,
        operation_registry: OperationRegistry = registry,
        policy: ExecutionPolicy | None = None,
    ) -> None:
        self.registry = operation_registry
        self.policy = policy

    def bake_result(
        self,
        value: Data,
        recipe: RecipeConfig | Recipe,
        *,
        return_type: Literal["str", "bytes"] | None = None,
        raise_errors: bool = True,
        policy: ExecutionPolicy | None = None,
        trace: bool = False,
    ) -> BakeResult:
        parsed = recipe if isinstance(recipe, Recipe) else Recipe(recipe)
        started = perf_counter()
        progress = 0
        error: Exception | None = None
        result: Data = value
        context = ExecutionContext(
            policy=policy or self.policy or ExecutionPolicy.permissive(), trace_enabled=trace
        )
        try:
            result, progress = parsed.execute(
                value, operation_registry=self.registry, context=context
            )
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
            trace=tuple(context.trace),
        )

    def bake(
        self,
        value: Data,
        recipe: RecipeConfig | Recipe,
        *,
        return_type: Literal["str", "bytes"] | None = None,
        policy: ExecutionPolicy | None = None,
    ) -> Data:
        return self.bake_result(value, recipe, return_type=return_type, policy=policy).result


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
    policy: ExecutionPolicy | None = None,
) -> Data:
    """Bake *value* with *recipe* and return the transformed value."""
    return Chef().bake(value, recipe, return_type=return_type, policy=policy)
