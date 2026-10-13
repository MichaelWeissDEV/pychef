"""Tests for lazy loading of operations and modules."""

from __future__ import annotations

import subprocess
import sys

import pytest

from pychef import list_operations, registry
from pychef.operations import by_operation


def test_lazy_loading_subprocess_verification() -> None:
    # Run an isolated python process to verify zero by_operation modules on import pychef
    code = """
import sys
import pychef

by_op_mods = [name for name in sys.modules if "pychef.operations.by_operation." in name]
assert len(by_op_mods) == 0, f"Expected 0 by_operation modules, got {by_op_mods}"

# Accessing one operation via registry should load ONLY that module
op = pychef.registry.get("To Base64")
assert op.name == "To Base64"

by_op_mods_after = [name for name in sys.modules if "pychef.operations.by_operation." in name]
assert len(by_op_mods_after) == 1
assert by_op_mods_after == ["pychef.operations.by_operation.to_base64"]
print("OK")
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "OK" in result.stdout


def test_registry_names_and_len_without_full_load() -> None:
    names = registry.names()
    assert len(names) == 502
    assert len(registry) == 502
    assert "To Hex" in registry
    assert "Unknown Operation" not in registry


def test_by_operation_getattr() -> None:
    mod = by_operation.to_base64
    assert mod.NAME == "To Base64"
    assert callable(mod.run)


def test_by_operation_load_all() -> None:
    # Ensure load_all imports everything without error
    by_operation.load_all()
    assert len(registry) == 502
    assert all(name in registry for name in list_operations())


def test_custom_registry_lazy_loads_and_isolates() -> None:
    from typing import Any

    from pychef import Operation, OperationRegistry

    custom = OperationRegistry()
    assert "To Hex" not in custom._operations
    # Getting "To Hex" must successfully lazy load and populate custom._operations
    op = custom.get("To Hex")
    assert op.name == "To Hex"
    assert "To Hex" in custom._operations
    assert custom.get("To Hex") is op

    # Custom override on custom registry does not affect global registry
    def custom_hex(val: Any, args: Any) -> Any:
        return "custom"

    custom_override = OperationRegistry()
    custom_override.register(Operation(name="To Hex", function=custom_hex))
    assert custom_override.get("To Hex").run("test") == "custom"
    assert registry.get("To Hex").run("test") != "custom"


def test_custom_registry_empty_manifest_strictly_isolated() -> None:
    from pychef import OperationRegistry, UnknownOperationError

    # Ensure "To Hex" is loaded in global registry
    _ = registry.get("To Hex")
    assert "To Hex" in registry._operations

    # An empty manifest registry must NEVER leak or fall back to global registry
    empty_reg = OperationRegistry(manifest={})
    assert len(empty_reg) == 0
    assert empty_reg.names() == ()
    assert "To Hex" not in empty_reg

    with pytest.raises(UnknownOperationError, match="unknown operation: To Hex"):
        empty_reg.get("To Hex")
