"""Shared public types and safe conversion helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

Data: TypeAlias = str | bytes
Args: TypeAlias = Sequence[Any]
RecipeConfig: TypeAlias = Sequence["RecipeStep | Mapping[str, Any] | str"]


def to_bytes(value: Data, encoding: str = "utf-8", errors: str = "strict") -> bytes:
    """Return *value* as bytes without silently using a locale encoding."""
    if isinstance(value, bytes):
        return value
    return value.encode(encoding, errors)


def to_text(value: Data, encoding: str = "utf-8", errors: str = "replace") -> str:
    """Return *value* as text with CyberChef-like replacement on invalid UTF-8."""
    if isinstance(value, str):
        return value
    return value.decode(encoding, errors)


@dataclass(frozen=True, slots=True)
class RecipeStep:
    """One immutable CyberChef-compatible recipe step."""

    op: str
    args: tuple[Any, ...] = ()
    disabled: bool = False
    breakpoint: bool = False


@dataclass(frozen=True, slots=True)
class TraceStep:
    """One recorded step.  Never contains data, only types and sizes."""

    operation: str
    step_index: int
    branch_path: tuple[int, ...]
    input_type: str
    output_type: str
    input_size: int
    output_size: int
    duration_ms: float
    error: str | None = None


@dataclass(frozen=True, slots=True)
class BakeResult:
    """Detailed result returned by :meth:`Chef.bake_result`."""

    result: Data
    type: Literal["string", "bytes"]
    progress: int
    duration_ms: float
    error: Exception | None = None
    trace: tuple[TraceStep, ...] = ()
