"""Composable, reusable transformation pipelines for Python and CTF scripts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from .errors import OperationError, RecipeError
from .execution import ExecutionContext, ExecutionPolicy, active_policy
from .recipe import Recipe
from .registry import OperationRegistry, registry
from .types import RecipeStep

Transform = Callable[[Any], Any]
PipelineStep = RecipeStep | Mapping[str, Any] | str


def _join_values(values: Sequence[Any], separator: str | bytes) -> str | bytes:
    if isinstance(separator, bytes):
        if not all(isinstance(value, bytes) for value in values):
            raise TypeError("a bytes separator requires every concatenated output to be bytes")
        return separator.join(values)
    if not all(isinstance(value, str) for value in values):
        raise TypeError("a string separator requires every concatenated output to be str")
    return separator.join(values)


def _measure_trace_size(val: Any) -> int:
    if isinstance(val, bytes):
        return len(val)
    if isinstance(val, str):
        return len(val.encode("utf-8", "surrogatepass"))
    try:
        return len(val)
    except (TypeError, Exception):
        return 0


def _truncate_preview(val: Any, limit: int) -> tuple[Any, bool]:
    if isinstance(val, str):
        raw = val.encode("utf-8", "surrogatepass")
        if len(raw) > limit:
            return raw[:limit].decode("utf-8", "ignore"), True
        return val, False
    if isinstance(val, bytes):
        if len(val) > limit:
            return val[:limit], True
        return val, False
    return val, False


@dataclass(frozen=True, slots=True)
class PipelineTrace:
    """The input and output captured for one pipeline stage."""

    name: str
    input: Any
    output: Any
    input_size: int = 0
    output_size: int = 0
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Stage:
    name: str
    transform: Transform
    recipe_step: RecipeStep | None = None

    def run(self, value: Any) -> Any:
        return self.transform(value)


class Pipeline:
    """An immutable chain of transformations.

    Each chaining method returns a new pipeline, so a configured instance can
    safely be reused for many inputs. CyberChef operations, ordinary Python
    callables, branches, and dictionary-producing packet parsers can be mixed.
    """

    __slots__ = ("_registry", "_stages")

    def __init__(
        self,
        steps: Iterable[PipelineStep] = (),
        *,
        operation_registry: OperationRegistry = registry,
        _stages: tuple[_Stage, ...] = (),
    ) -> None:
        self._registry = operation_registry
        parsed_stages = list(_stages)
        for step in steps:
            parsed = Recipe([step]).steps[0]
            parsed_stages.append(self._operation_stage(parsed))
        self._stages = tuple(parsed_stages)

    def _new(self, *stages: _Stage) -> Pipeline:
        return Pipeline(operation_registry=self._registry, _stages=self._stages + stages)

    def _operation_stage(self, step: RecipeStep) -> _Stage:
        def run(value: Any) -> Any:
            if not isinstance(value, (str, bytes)):
                raise TypeError(
                    f"CyberChef operation {step.op!r} needs str or bytes, "
                    f"not {type(value).__name__}"
                )
            if step.disabled or step.op == "Comment":
                return value
            try:
                return self._registry.get(step.op).run(value, step.args)
            except OperationError:
                raise
            except Exception as exc:
                raise OperationError(step.op, str(exc)) from exc

        return _Stage(step.op, run, step)

    @property
    def steps(self) -> tuple[str, ...]:
        """Return the human-readable names of all configured stages."""
        return tuple(stage.name for stage in self._stages)

    @property
    def recipe(self) -> Recipe:
        """Return this pipeline as a recipe if it only contains operations."""
        recipe_steps = tuple(stage.recipe_step for stage in self._stages)
        if any(step is None for step in recipe_steps):
            raise RecipeError("pipeline contains Python or branching stages and is not a recipe")
        return Recipe([step for step in recipe_steps if step is not None])

    def then(self, operation: str | RecipeStep | Mapping[str, Any], *args: Any) -> Pipeline:
        """Append any registered CyberChef operation."""
        if isinstance(operation, str):
            step = RecipeStep(operation, tuple(args))
        else:
            if args:
                raise TypeError("positional arguments are only valid with an operation name")
            step = Recipe([operation]).steps[0]
        return self._new(self._operation_stage(step))

    operation = then

    def apply(self, transform: Transform, *, name: str | None = None) -> Pipeline:
        """Append an arbitrary Python callable."""
        if not callable(transform):
            raise TypeError("transform must be callable")
        stage_name = name or getattr(transform, "__name__", transform.__class__.__name__)
        return self._new(_Stage(str(stage_name), transform))

    def concat(
        self,
        *branches: Pipeline | Transform,
        separator: str | bytes = b"",
    ) -> Pipeline:
        """Run every branch on the current value and concatenate its outputs."""
        if not branches:
            raise ValueError("concat needs at least one branch")
        normalized = tuple(
            branch if isinstance(branch, Pipeline) else Pipeline().apply(branch)
            for branch in branches
        )

        def concatenate(value: Any) -> str | bytes:
            return _join_values(tuple(branch.transform(value) for branch in normalized), separator)

        names = ", ".join(" -> ".join(branch.steps) or "identity" for branch in normalized)
        return self._new(_Stage(f"concat({names})", concatenate))

    def append(self, suffix: str | bytes) -> Pipeline:
        """Append a constant to each transformed output without coercing types."""
        separator: str | bytes = b"" if isinstance(suffix, bytes) else ""
        return self.concat(Pipeline(), lambda _value: suffix, separator=separator)

    def prepend(self, prefix: str | bytes) -> Pipeline:
        """Prepend a constant to each transformed output without coercing types."""
        separator: str | bytes = b"" if isinstance(prefix, bytes) else ""
        return self.concat(lambda _value: prefix, Pipeline(), separator=separator)

    def select(self, *path: str | int) -> Pipeline:
        """Select nested mapping keys, sequence indexes, or object attributes."""
        if not path:
            raise ValueError("select needs at least one path component")

        def select_value(value: Any) -> Any:
            current = value
            for component in path:
                if isinstance(current, Mapping) or (
                    isinstance(component, int) and isinstance(current, Sequence)
                ):
                    current = current[component]
                elif isinstance(component, str):
                    current = getattr(current, component)
                else:
                    raise TypeError(f"cannot select {component!r} from {type(current).__name__}")
            return current

        return self._new(_Stage("select(" + ", ".join(map(str, path)) + ")", select_value))

    def transform(
        self,
        value: Any,
        *,
        policy: ExecutionPolicy | None = None,
        context: ExecutionContext | None = None,
    ) -> Any:
        """Transform one value through every configured stage."""
        if context is None:
            context = ExecutionContext(policy=policy or ExecutionPolicy.safe())
        elif policy is not None and policy is not context.policy:
            raise ValueError("pass either policy or context, not both")

        with active_policy(context.policy):
            if isinstance(value, (str, bytes)):
                context.check_input(value)
            for index, stage in enumerate(self._stages):
                context.charge_step(stage.name, index)
                if stage.recipe_step is not None:
                    context.require_operation(stage.recipe_step.op, index)
                started = perf_counter()
                before = value
                try:
                    value = stage.run(value)
                except OperationError as exc:
                    if exc.step_index is None:
                        exc.step_index = index
                        exc.branch_path = context.branch_path
                        exc.execution_id = context.execution_id
                    if isinstance(before, (str, bytes)):
                        context.record(stage.name, index, before, None, started, exc)
                    raise
                except Exception as exc:
                    if isinstance(before, (str, bytes)):
                        context.record(stage.name, index, before, None, started, exc)
                    raise
                if isinstance(before, (str, bytes)) and isinstance(value, (str, bytes)):
                    context.record(stage.name, index, before, value, started, None)
                if isinstance(value, (str, bytes)):
                    context.check_output(value, stage.name, index)
            return value

    run = transform
    bake = transform
    __call__ = transform

    def iter_transform(
        self,
        values: Iterable[Any],
        *,
        policy: ExecutionPolicy | None = None,
    ) -> Iterator[Any]:
        """Stream transformations across *values* without buffering the full sequence."""
        context = ExecutionContext(policy=policy or ExecutionPolicy.safe())
        for item in values:
            yield self.transform(item, context=context)

    def transform_many(
        self,
        values: Iterable[Any],
        *,
        policy: ExecutionPolicy | None = None,
    ) -> tuple[Any, ...]:
        """Transform a finite iterable while retaining input order."""
        return tuple(self.iter_transform(values, policy=policy))

    def trace(
        self,
        value: Any,
        *,
        policy: ExecutionPolicy | None = None,
        context: ExecutionContext | None = None,
        max_preview_bytes: int | None = None,
    ) -> tuple[PipelineTrace, ...]:
        """Run the pipeline and retain intermediate inputs and outputs.

        Enforces identical policy, step budget, deadline, and network constraints as
        :meth:`transform`. Intermediate trace sizes are bounded by
        ``policy.max_trace_bytes``.
        """
        if max_preview_bytes is not None and (
            isinstance(max_preview_bytes, bool)
            or not isinstance(max_preview_bytes, int)
            or max_preview_bytes < 0
        ):
            raise ValueError("max_preview_bytes must be None or a non-negative integer")

        if context is None:
            context = ExecutionContext(policy=policy or ExecutionPolicy.safe(), trace_enabled=True)
        elif policy is not None and policy is not context.policy:
            raise ValueError("pass either policy or context, not both")

        accumulated_trace_bytes = 0
        limit_trace_bytes = context.policy.max_trace_bytes

        with active_policy(context.policy):
            if isinstance(value, (str, bytes)):
                context.check_input(value)

            trace: list[PipelineTrace] = []
            for index, stage in enumerate(self._stages):
                context.charge_step(stage.name, index)
                if stage.recipe_step is not None:
                    context.require_operation(stage.recipe_step.op, index)

                started = perf_counter()
                stage_input = value
                try:
                    value = stage.run(value)
                except OperationError as exc:
                    if exc.step_index is None:
                        exc.step_index = index
                        exc.branch_path = context.branch_path
                        exc.execution_id = context.execution_id
                    if isinstance(stage_input, (str, bytes)):
                        context.record(stage.name, index, stage_input, None, started, exc)
                    raise
                except Exception as exc:
                    if isinstance(stage_input, (str, bytes)):
                        context.record(stage.name, index, stage_input, None, started, exc)
                    raise

                if isinstance(stage_input, (str, bytes)) and isinstance(value, (str, bytes)):
                    context.record(stage.name, index, stage_input, value, started, None)
                if isinstance(value, (str, bytes)):
                    context.check_output(value, stage.name, index)

                # Track size of inputs/outputs for trace bounding
                in_size = _measure_trace_size(stage_input)
                out_size = _measure_trace_size(value)

                accumulated_trace_bytes += in_size + out_size + 64
                if limit_trace_bytes is not None and accumulated_trace_bytes > limit_trace_bytes:
                    raise context._limit(
                        "max_trace_bytes",
                        f"trace buffer exceeded {limit_trace_bytes} bytes",
                        stage.name,
                        index,
                    )

                saved_in = stage_input
                saved_out = value
                truncated = False
                if max_preview_bytes is not None:
                    saved_in, in_trunc = _truncate_preview(stage_input, max_preview_bytes)
                    saved_out, out_trunc = _truncate_preview(value, max_preview_bytes)
                    truncated = in_trunc or out_trunc

                trace.append(
                    PipelineTrace(
                        name=stage.name,
                        input=saved_in,
                        output=saved_out,
                        input_size=in_size,
                        output_size=out_size,
                        truncated=truncated,
                    )
                )

            return tuple(trace)

    def from_hex(self, delimiter: str = "Auto") -> Pipeline:
        return self.then("From Hex", delimiter)

    def to_hex(self, delimiter: str = "None", bytes_per_line: int = 0) -> Pipeline:
        return self.then("To Hex", delimiter, bytes_per_line)

    def from_base64(self, alphabet: str = "A-Za-z0-9+/=", strict: bool = False) -> Pipeline:
        return self.then("From Base64", alphabet, True, strict)

    def to_base64(self, alphabet: str = "A-Za-z0-9+/=") -> Pipeline:
        return self.then("To Base64", alphabet)

    def decode(self, encoding: str = "UTF-8 (65001)") -> Pipeline:
        return self.then("Decode text", encoding)

    def encode(self, encoding: str = "UTF-8 (65001)") -> Pipeline:
        return self.then("Encode text", encoding)

    def digest(self, algorithm: str = "sha256", *, output: str = "hex") -> Pipeline:
        from .ctf import digest

        return self.apply(
            lambda value: digest(value, algorithm=algorithm, output=output),
            name=f"digest({algorithm}, {output})",
        )

    def xor(self, key: str | bytes, *, key_format: str = "raw") -> Pipeline:
        from .ctf import decode_bytes, xor_bytes

        decoded_key = decode_bytes(key, format=key_format)
        return self.apply(lambda value: xor_bytes(value, decoded_key), name="xor")

    def swap_endian(self, word_size: int = 4, *, strict: bool = True) -> Pipeline:
        from .ctf import swap_endian

        return self.apply(
            lambda value: swap_endian(value, word_size, strict=strict),
            name=f"swap endian ({word_size} bytes)",
        )

    def unpack(
        self,
        bits: int = 32,
        *,
        endian: str = "little",
        signed: bool = False,
        offset: int = 0,
    ) -> Pipeline:
        from .ctf import unpack

        return self.apply(
            lambda value: unpack(value, bits, endian=endian, signed=signed, offset=offset),
            name=f"unpack {bits}-bit {endian}",
        )

    def pack(
        self,
        bits: int = 32,
        *,
        endian: str = "little",
        signed: bool = False,
    ) -> Pipeline:
        from .ctf import pack

        return self.apply(
            lambda value: pack(value, bits, endian=endian, signed=signed),
            name=f"pack {bits}-bit {endian}",
        )

    def hexdump(self, *, width: int = 16, start: int = 0) -> Pipeline:
        from .ctf import hexdump

        return self.apply(
            lambda value: hexdump(value, width=width, start=start),
            name="hexdump",
        )

    def parse_packet(self, *, link_type: int = 1) -> Pipeline:
        from .packets import parse_packet

        return self.apply(
            lambda value: parse_packet(value, link_type=link_type),
            name=f"parse packet ({link_type})",
        )

    def parse_capture(
        self,
        *,
        max_packets: int | None = 100_000,
        max_packet_size: int | None = 16 * 1024 * 1024,
    ) -> Pipeline:
        from .packets import parse_capture

        return self.apply(
            lambda value: parse_capture(
                value,
                max_packets=max_packets,
                max_packet_size=max_packet_size,
            ),
            name="parse capture",
        )

    from_pcap = parse_capture

    def aes_encrypt(
        self,
        key: str | bytes,
        *,
        mode: str = "CBC",
        iv: str | bytes | None = None,
        padding: str = "pkcs7",
        aad: str | bytes = b"",
        key_format: str = "raw",
        iv_format: str = "raw",
        append_tag: bool = True,
    ) -> Pipeline:
        from .ctf import aes_encrypt

        return self.apply(
            lambda value: aes_encrypt(
                value,
                key,
                mode=mode,
                iv=iv,
                padding=padding,
                aad=aad,
                key_format=key_format,
                iv_format=iv_format,
                append_tag=append_tag,
            ),
            name=f"AES {mode.upper()} encrypt",
        )

    def aes_decrypt(
        self,
        key: str | bytes,
        *,
        mode: str = "CBC",
        iv: str | bytes | None = None,
        padding: str = "pkcs7",
        aad: str | bytes = b"",
        tag: str | bytes | None = None,
        key_format: str = "raw",
        iv_format: str = "raw",
        tag_format: str = "raw",
    ) -> Pipeline:
        from .ctf import aes_decrypt

        return self.apply(
            lambda value: aes_decrypt(
                value,
                key,
                mode=mode,
                iv=iv,
                padding=padding,
                aad=aad,
                tag=tag,
                key_format=key_format,
                iv_format=iv_format,
                tag_format=tag_format,
            ),
            name=f"AES {mode.upper()} decrypt",
        )

    def __or__(self, other: Pipeline) -> Pipeline:
        if not isinstance(other, Pipeline):
            return NotImplemented
        if self._registry is not other._registry:
            raise ValueError("pipelines use different operation registries")
        return Pipeline(
            operation_registry=self._registry,
            _stages=self._stages + other._stages,
        )

    def __ror__(self, value: Any) -> Any:
        return self.transform(value)

    def __len__(self) -> int:
        return len(self._stages)

    def __repr__(self) -> str:
        return f"Pipeline({self.steps!r})"


__all__ = ["Pipeline", "PipelineStep", "PipelineTrace", "Transform"]
