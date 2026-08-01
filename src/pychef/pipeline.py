"""Composable, reusable transformation pipelines for Python and CTF scripts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .errors import OperationError, RecipeError
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


@dataclass(frozen=True, slots=True)
class PipelineTrace:
    """The input and output captured for one pipeline stage."""

    name: str
    input: Any
    output: Any


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

    def transform(self, value: Any) -> Any:
        """Transform one value through every configured stage."""
        for stage in self._stages:
            value = stage.run(value)
        return value

    run = transform
    bake = transform
    __call__ = transform

    def transform_many(self, values: Iterable[Any]) -> tuple[Any, ...]:
        """Transform a finite iterable while retaining input order."""
        return tuple(self.transform(value) for value in values)

    def trace(self, value: Any) -> tuple[PipelineTrace, ...]:
        """Run the pipeline and retain every intermediate input and output."""
        trace: list[PipelineTrace] = []
        for stage in self._stages:
            stage_input = value
            value = stage.run(value)
            trace.append(PipelineTrace(stage.name, stage_input, value))
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
        max_packets: int = 100_000,
        max_packet_size: int = 16 * 1024 * 1024,
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
