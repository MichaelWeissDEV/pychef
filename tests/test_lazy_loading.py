"""Tests for lazy loading of operations and modules."""

from __future__ import annotations

import subprocess
import sys

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
