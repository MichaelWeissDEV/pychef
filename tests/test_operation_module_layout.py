"""Enforce the one-public-module-per-operation architecture."""

from __future__ import annotations

import importlib
import keyword
import re

from pychef import list_operations, registry
from pychef.operations.by_operation import MODULES


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return f"{slug}_operation" if keyword.iskeyword(slug) else slug


def test_every_operation_has_exactly_one_dedicated_module() -> None:
    names = list_operations()
    assert len(names) == len(MODULES) == len(set(MODULES)) == 502
    assert tuple(_slug(name) for name in names) == MODULES
    for name, module_name in zip(names, MODULES, strict=True):
        module = importlib.import_module(f"pychef.operations.by_operation.{module_name}")
        assert name == module.NAME
        assert module.run is registry.get(name).function
        assert module.run.__module__ == f"pychef.operations.by_operation.{module_name}"


def test_shared_implementation_modules_do_not_register_operations() -> None:
    assert all(
        operation.function.__module__.startswith("pychef.operations.by_operation.")
        for operation in registry
    )
