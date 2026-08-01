"""Thread-safe operation registry."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from threading import RLock
from typing import Any, cast

from .errors import UnknownOperationError
from .types import Args, Data

OperationFunction = Callable[[Data, Args], Data]


@dataclass(frozen=True, slots=True)
class Operation:
    """Metadata and implementation for a registered operation."""

    name: str
    function: OperationFunction
    category: str = ""

    def run(self, value: Data, args: Args = ()) -> Data:
        return self.function(value, args)


class OperationRegistry:
    """Case-sensitive registry matching CyberChef's public operation names."""

    def __init__(self) -> None:
        self._operations: dict[str, Operation] = {}
        self._lock = RLock()

    def register(self, operation: Operation) -> None:
        with self._lock:
            if operation.name in self._operations:
                raise ValueError(f"operation already registered: {operation.name}")
            self._operations[operation.name] = operation

    def get(self, name: str) -> Operation:
        try:
            return self._operations[name]
        except KeyError as exc:
            raise UnknownOperationError(f"unknown operation: {name}") from exc

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._operations))

    def __contains__(self, name: object) -> bool:
        return name in self._operations

    def __len__(self) -> int:
        return len(self._operations)

    def __iter__(self) -> Iterator[Operation]:
        with self._lock:
            yield from tuple(self._operations.values())


registry = OperationRegistry()


def operation(name: str, *, category: str = "") -> Callable[[OperationFunction], OperationFunction]:
    """Register a function under an exact CyberChef operation name."""

    def decorator(function: OperationFunction) -> OperationFunction:
        registry.register(Operation(name=name, function=function, category=category))
        return function

    return decorator


def implementation(
    name: str, *, category: str = ""
) -> Callable[[OperationFunction], OperationFunction]:
    """Annotate a shared implementation without registering it directly.

    Built-in operations are registered by their dedicated modules under
    :mod:`pychef.operations.by_operation`. Keeping this lightweight decorator
    on shared implementations retains readable operation metadata next to the
    algorithm while ensuring that every public operation has exactly one file.
    """

    def decorator(function: OperationFunction) -> OperationFunction:
        metadata_target = cast(Any, function)
        metadata_target.__pychef_operation_name__ = name
        metadata_target.__pychef_operation_category__ = category
        return function

    return decorator
