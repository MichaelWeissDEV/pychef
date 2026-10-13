"""Thread-safe operation registry with on-demand lazy loading."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Any, cast

from .errors import UnknownOperationError
from .manifest import OPERATION_MODULES
from .types import Args, Data

if TYPE_CHECKING:
    from .spec import OperationSpec

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

    def __init__(self, manifest: Mapping[str, str] | None = None) -> None:
        self._operations: dict[str, Operation] = {}
        self._manifest: dict[str, str] = (
            dict(manifest) if manifest is not None else dict(OPERATION_MODULES)
        )
        self._lock = RLock()

    def register(self, operation: Operation) -> None:
        with self._lock:
            existing = self._operations.get(operation.name)
            if existing is not None and existing.function is not operation.function:
                raise ValueError(f"operation already registered: {operation.name}")
            self._operations[operation.name] = operation

    def get(self, name: str) -> Operation:
        op = self._operations.get(name)
        if op is not None:
            return op
        with self._lock:
            op = self._operations.get(name)
            if op is not None:
                return op
            module_slug = self._manifest.get(name)
            if module_slug is not None:
                importlib.import_module(f"pychef.operations.by_operation.{module_slug}")
                op = self._operations.get(name)
                if op is not None:
                    return op
                if name in registry._operations:
                    global_op = registry._operations[name]
                    self._operations[name] = global_op
                    return global_op
            elif name in registry._operations:
                global_op = registry._operations[name]
                self._operations[name] = global_op
                return global_op
            raise UnknownOperationError(f"unknown operation: {name}")

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(set(self._manifest) | set(self._operations)))

    def spec(self, name: str) -> OperationSpec:
        """Return the structured specification for *name*."""
        from .spec import get_operation_spec

        return get_operation_spec(name)

    def specs(self) -> tuple[OperationSpec, ...]:
        """Return structured specifications for all known operations."""
        from .spec import list_operation_specs

        return list_operation_specs()

    def __contains__(self, name: object) -> bool:
        return name in self._operations or name in self._manifest

    def __len__(self) -> int:
        return len(set(self._manifest) | set(self._operations))

    def __iter__(self) -> Iterator[Operation]:
        for name in self.names():
            yield self.get(name)


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
