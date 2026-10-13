"""Tests for OperationSpec and metadata API."""

from __future__ import annotations

import pytest

from pychef import (
    OperationArgSpec,
    OperationSpec,
    UnknownOperationError,
    get_operation_spec,
    list_operation_specs,
    registry,
)


def test_get_operation_spec() -> None:
    spec = get_operation_spec("AES Encrypt")
    assert isinstance(spec, OperationSpec)
    assert spec.name == "AES Encrypt"
    assert spec.category == "Ciphers"
    assert spec.input_type in {"string", "byteArray"}
    assert spec.output_type in {"string", "byteArray"}
    assert len(spec.arguments) > 0
    assert all(isinstance(arg, OperationArgSpec) for arg in spec.arguments)
    assert spec.arguments[0].name == "Key"


def test_list_operation_specs() -> None:
    specs = list_operation_specs()
    assert len(specs) == 502
    assert all(isinstance(s, OperationSpec) for s in specs)
    # Check stable alphabetical ordering
    names = [s.name for s in specs]
    assert names == sorted(names)


def test_registry_spec_delegation() -> None:
    spec1 = registry.spec("To Hex")
    assert spec1.name == "To Hex"
    specs = registry.specs()
    assert len(specs) == 502


def test_get_operation_spec_unknown() -> None:
    with pytest.raises(UnknownOperationError):
        get_operation_spec("Non Existent Operation 12345")


def test_spec_to_dict_serialization() -> None:
    spec = get_operation_spec("To Base64")
    data = spec.to_dict()
    assert data["name"] == "To Base64"
    assert "arguments" in data
    assert isinstance(data["arguments"], list)
    if data["arguments"]:
        arg = data["arguments"][0]
        assert "name" in arg
        assert "type" in arg
        assert "default" in arg
