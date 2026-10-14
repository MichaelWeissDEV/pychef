"""CyberChef-compatible recipe parsing and execution."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import suppress
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
    """A validated, reusable sequence of data transformation operations.

    ``steps`` exposes the parsed :class:`RecipeStep` tuple. A recipe is immutable
    in practice and can be executed any number of times with :meth:`execute`,
    :func:`bake`, or :meth:`Chef.bake`.
    """

    def __init__(self, config: RecipeConfig) -> None:
        self.steps = tuple(self._parse_step(step) for step in config)

    def __repr__(self) -> str:
        return f"Recipe({[step.op for step in self.steps]!r})"

    def __len__(self) -> int:
        return len(self.steps)

    def to_config(self) -> list[dict[str, Any]]:
        """Return the recipe as CyberChef-style step dictionaries.

        The result can be passed back to :class:`Recipe` or :func:`bake`. Step
        arguments are returned unchanged, so they may contain non-JSON values.
        """
        return [
            {
                "op": step.op,
                "args": list(step.args),
                **({"disabled": True} if step.disabled else {}),
                **({"breakpoint": True} if step.breakpoint else {}),
            }
            for step in self.steps
        ]

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the recipe to JSON text.

        Raises :class:`TypeError` if an argument is not JSON serializable (for
        example ``bytes``). A structurally valid recipe is not guaranteed to be
        accepted by every operation: arguments are only validated when it runs.
        """
        return json.dumps(self.to_config(), indent=indent)

    @classmethod
    def from_json(cls, text: str | bytes) -> Recipe:
        """Build a recipe from JSON text such as :meth:`to_json` produces.

        The JSON document must be a list of steps (strings or objects with ``op``
        and optional ``args``).
        """
        try:
            config = json.loads(text)
        except ValueError as exc:
            raise RecipeError(f"recipe is not valid JSON: {exc}") from exc
        if not isinstance(config, list):
            raise RecipeError("a JSON recipe must be a list of steps")
        return cls(config)

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

        Without *policy* or *context*, safe default limits
        (:meth:`ExecutionPolicy.safe`) apply. A *context* may be shared
        to account several executions against one budget.
        """
        if context is None:
            context = ExecutionContext(policy=policy or ExecutionPolicy.safe())
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
                    raw_split = str(step.args[0] if step.args else "\n")
                    raw_merge = str(step.args[1] if len(step.args) > 1 else "\n")
                    if ctx.policy.max_input_bytes is not None:
                        if (
                            len(raw_split.encode("utf-8", "surrogatepass"))
                            > ctx.policy.max_input_bytes
                        ):
                            ctx.check_input(raw_split, step.op, abs_index)
                        if (
                            len(raw_merge.encode("utf-8", "surrogatepass"))
                            > ctx.policy.max_input_bytes
                        ):
                            ctx.check_input(raw_merge, step.op, abs_index)
                    split_delimiter = _binary_delimiter(raw_split)
                    merge_delimiter = _binary_delimiter(raw_merge)
                    outputs: list[str] = []
                    text = to_text(value)
                    accumulated_bytes = 0
                    merge_delim_bytes = len(merge_delimiter.encode("utf-8", "surrogatepass"))
                    for part in _split_iter(text, split_delimiter):
                        ctx.charge_branch(step.op, abs_index)
                        try:
                            with ctx.nested(step.op, abs_index):
                                transformed_res = Recipe(substeps)._run(
                                    part, operation_registry, ctx, base + index + 1
                                )[0]
                        except _FATAL_ERRORS:
                            raise
                        except Exception:
                            if not ignore_errors:
                                raise
                            transformed_res = part
                        part_str = to_text(transformed_res)
                        outputs.append(part_str)
                        delim_cost = merge_delim_bytes if len(outputs) > 1 else 0
                        accumulated_bytes += (
                            len(part_str.encode("utf-8", "surrogatepass")) + delim_cost
                        )
                        ctx.check_output(accumulated_bytes, step.op, abs_index)
                    value = merge_delimiter.join(outputs)
                else:
                    pattern = str(step.args[0] if step.args else "")
                    if (
                        ctx.policy.max_input_bytes is not None
                        and len(pattern.encode("utf-8", "surrogatepass"))
                        > ctx.policy.max_input_bytes
                    ):
                        ctx.check_input(pattern, step.op, abs_index)
                    flags = 0 if len(step.args) < 2 or step.args[1] else re.IGNORECASE
                    global_matching = bool(step.args[2] if len(step.args) > 2 else True)
                    source = to_text(value)
                    matches = (
                        _compile(pattern, flags, step.op, abs_index, ctx).finditer(source)
                        if pattern
                        else iter(())
                    )
                    output: list[str] = []
                    cursor = 0
                    accumulated_bytes = 0
                    for match in matches:
                        selected = match.group(1) if match.groups() else match.group(0)
                        start, end = match.span(1) if match.groups() else match.span(0)
                        prefix = source[cursor:start]
                        output.append(prefix)
                        accumulated_bytes += len(prefix.encode("utf-8", "surrogatepass"))
                        ctx.check_output(accumulated_bytes, step.op, abs_index)
                        ctx.charge_branch(step.op, abs_index)
                        try:
                            with ctx.nested(step.op, abs_index):
                                transformed_sub = Recipe(substeps)._run(
                                    selected, operation_registry, ctx, base + index + 1
                                )[0]
                        except _FATAL_ERRORS:
                            raise
                        except Exception:
                            if not ignore_errors:
                                raise
                            transformed_sub = selected
                        sub_str = to_text(transformed_sub)
                        output.append(sub_str)
                        accumulated_bytes += len(sub_str.encode("utf-8", "surrogatepass"))
                        ctx.check_output(accumulated_bytes, step.op, abs_index)
                        cursor = end
                        if not global_matching:
                            break
                    suffix = source[cursor:]
                    output.append(suffix)
                    accumulated_bytes += len(suffix.encode("utf-8", "surrogatepass"))
                    ctx.check_output(accumulated_bytes, step.op, abs_index)
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
                exc.message = _sanitize_error_message(exc.message, step.args, before)
                exc.args = (f"{exc.operation}: {exc.message}",)
                if exc.step_index is None:
                    exc.step_index = abs_index
                    exc.branch_path = ctx.branch_path
                    exc.execution_id = ctx.execution_id
                ctx.record(step.op, abs_index, before, None, started, exc)
                raise
            except Exception as exc:
                sanitized_msg = _sanitize_error_message(str(exc), step.args, before)
                error = OperationError(
                    step.op,
                    sanitized_msg,
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


_SAFE_ERROR_WORDS = frozenset(
    {
        "aes",
        "des",
        "triple des",
        "blowfish",
        "twofish",
        "rc2",
        "rc4",
        "rc6",
        "cast-128",
        "cast-256",
        "seed",
        "sm4",
        "aria",
        "camellia",
        "gost 28147-89",
        "argon2i",
        "argon2d",
        "argon2id",
        "bcrypt",
        "scrypt",
        "pbkdf2",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "sha3",
        "blake2b",
        "blake2s",
        "raw",
        "hex",
        "base64",
        "utf8",
        "utf-8",
        "ascii",
        "latin1",
        "none",
        "auto",
        "true",
        "false",
        "invalid",
        "valid",
        "error",
        "cbc",
        "ecb",
        "cfb",
        "ofb",
        "ctr",
        "gcm",
        "ccm",
        "encoded hash",
        "raw hash",
        "hex hash",
    }
)


def _sanitize_error_message(message: str, args: Sequence[Any] = (), value: Any = None) -> str:
    """Sanitize exception messages to prevent leaking sensitive arguments and data."""
    sanitized = message

    def extract_secrets(obj: Any) -> list[str]:
        secrets: list[str] = []
        if isinstance(obj, str):
            if len(obj) >= 4 and obj.lower() not in _SAFE_ERROR_WORDS:
                secrets.append(obj)
        elif isinstance(obj, bytes):
            if len(obj) >= 4:
                with suppress(UnicodeError):
                    text = obj.decode("utf-8", "surrogatepass")
                    if text.lower() not in _SAFE_ERROR_WORDS:
                        secrets.append(text)
        elif isinstance(obj, Mapping):
            for k, v in obj.items():
                if k == "string" and isinstance(v, (str, bytes)):
                    val_str = v if isinstance(v, str) else v.decode("utf-8", "surrogatepass")
                    if len(val_str) >= 4 and val_str.lower() not in _SAFE_ERROR_WORDS:
                        secrets.append(val_str)
                else:
                    secrets.extend(extract_secrets(v))
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                secrets.extend(extract_secrets(v))
        return secrets

    all_secrets = extract_secrets(args)
    if value is not None:
        all_secrets.extend(extract_secrets(value))

    for secret in all_secrets:
        if secret in sanitized:
            sanitized = sanitized.replace(secret, "[REDACTED]")

    # Redact common credentials patterns
    sanitized = re.sub(
        r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]+=*",
        r"\1 [REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(session|token|auth|cookie2?)=([A-Za-z0-9._~+/-]+)",
        r"\1=[REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(api[_-]?key|password|secret|passphrase)\s*[:=]\s*[^\s,;]+",
        r"\1: [REDACTED]",
        sanitized,
    )

    return sanitized


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


def _split_iter(text: str, delimiter: str) -> Iterator[str]:
    """Iterate over parts split by *delimiter* without buffering full lists."""
    if not text:
        return
    if delimiter == "":
        yield from text
        return
    start = 0
    delim_len = len(delimiter)
    while True:
        pos = text.find(delimiter, start)
        if pos == -1:
            yield text[start:]
            break
        yield text[start:pos]
        start = pos + delim_len


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
        if isinstance(raw, (bool, float)):
            raise ValueError("boolean or float")
        if isinstance(raw, str):
            if "." in raw or "e" in raw.lower():
                raise ValueError("float string")
            maximum = int(raw)
        elif isinstance(raw, int):
            maximum = raw
        else:
            raise TypeError("unsupported type")
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
        isolated: bool = False,
    ) -> None:
        self.registry = operation_registry
        self.policy = policy
        self.isolated = isolated

    def bake_result(
        self,
        value: Data,
        recipe: RecipeConfig | Recipe,
        *,
        return_type: Literal["str", "bytes"] | None = None,
        raise_errors: bool = True,
        policy: ExecutionPolicy | None = None,
        trace: bool = False,
        isolated: bool | None = None,
    ) -> BakeResult:
        use_isolated = self.isolated if isolated is None else isolated
        eff_policy = policy or self.policy or ExecutionPolicy.safe()
        if use_isolated:
            from .worker import IsolatedWorker

            worker = IsolatedWorker(policy=eff_policy, operation_registry=self.registry)
            started = perf_counter()
            try:
                return worker.run(
                    value,
                    recipe,
                    return_type=return_type,
                    trace=trace,
                    operation_registry=self.registry,
                )
            except Exception as exc:
                if raise_errors:
                    raise
                duration_ms = (perf_counter() - started) * 1000
                return BakeResult(
                    result=value,
                    type="bytes" if isinstance(value, bytes) else "string",
                    progress=0,
                    duration_ms=duration_ms,
                    error=exc,
                    trace=(),
                )

        parsed = recipe if isinstance(recipe, Recipe) else Recipe(recipe)
        started = perf_counter()
        progress = 0
        error: Exception | None = None
        result: Data = value
        context = ExecutionContext(policy=eff_policy, trace_enabled=trace)
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
        isolated: bool | None = None,
    ) -> Data:
        return self.bake_result(
            value, recipe, return_type=return_type, policy=policy, isolated=isolated
        ).result


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
    isolated: bool = False,
) -> Data:
    """Bake *value* with *recipe* and return the transformed value."""
    return Chef(policy=policy, isolated=isolated).bake(
        value, recipe, return_type=return_type, isolated=isolated
    )
