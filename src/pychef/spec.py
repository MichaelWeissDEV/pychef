"""Operation specification and metadata API."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from threading import RLock
from typing import Any

from .errors import UnknownOperationError


@dataclass(frozen=True, slots=True)
class OperationArgSpec:
    """Specification of an operation argument."""

    name: str
    type: str
    default: Any = None
    choices: tuple[Any, ...] = ()
    toggle_values: tuple[Any, ...] = ()
    index: int = 0
    upstream_expression: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "default": self.default,
            "choices": list(self.choices),
            "toggle_values": list(self.toggle_values),
            "index": self.index,
            "upstream_expression": self.upstream_expression,
        }


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """CyberChef operation specification and metadata."""

    name: str
    description: str
    module: str
    input_type: str
    output_type: str
    arguments: tuple[OperationArgSpec, ...] = ()
    flow_control: bool = False
    manual_bake: bool = False
    info_url: str = ""
    upstream_file: str = ""

    @property
    def category(self) -> str:
        """Alias for module to match PyChef category naming."""
        return self.module

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "module": self.module,
            "category": self.category,
            "input_type": self.input_type,
            "output_type": self.output_type,
            "flow_control": self.flow_control,
            "manual_bake": self.manual_bake,
            "info_url": self.info_url,
            "upstream_file": self.upstream_file,
            "arguments": [arg.to_dict() for arg in self.arguments],
        }


_SPECS_CACHE: dict[str, OperationSpec] | None = None
_SPECS_LOCK = RLock()


def _find_metadata_path() -> Path:
    # 1. Look inside package data directory
    try:
        data_file = resources.files("pychef").joinpath("_data/cyberchef_operations.json")
        path = Path(str(data_file))
        if path.is_file():
            return path
    except Exception:
        pass

    # 2. File-relative check inside src/pychef/_data
    local_path = Path(__file__).resolve().parent / "_data" / "cyberchef_operations.json"
    if local_path.is_file():
        return local_path

    # 3. Fallback to docs/_data in development repo
    repo_docs_path = (
        Path(__file__).resolve().parents[2] / "docs" / "_data" / "cyberchef_operations.json"
    )
    if repo_docs_path.is_file():
        return repo_docs_path

    raise FileNotFoundError("Could not locate cyberchef_operations.json metadata file")


def load_specs() -> dict[str, OperationSpec]:
    """Load and parse operation specifications from cyberchef_operations.json."""
    global _SPECS_CACHE
    if _SPECS_CACHE is not None:
        return _SPECS_CACHE

    with _SPECS_LOCK:
        if _SPECS_CACHE is not None:
            return _SPECS_CACHE

        path = _find_metadata_path()
        with open(path, encoding="utf-8") as file:
            payload = json.load(file)

        specs: dict[str, OperationSpec] = {}
        for entry in payload.get("operations", []):
            args = tuple(
                OperationArgSpec(
                    name=str(arg.get("name", "")),
                    type=str(arg.get("type", "")),
                    default=arg.get("default"),
                    choices=tuple(arg.get("choices", ())),
                    toggle_values=tuple(arg.get("toggle_values", ())),
                    index=int(arg.get("index", 0)),
                    upstream_expression=str(arg.get("upstream_expression", "")),
                )
                for arg in entry.get("arguments", [])
            )
            spec = OperationSpec(
                name=str(entry.get("name", "")),
                description=str(entry.get("description", "")),
                module=str(entry.get("module", "")),
                input_type=str(entry.get("input_type", "")),
                output_type=str(entry.get("output_type", "")),
                arguments=args,
                flow_control=bool(entry.get("flow_control", False)),
                manual_bake=bool(entry.get("manual_bake", False)),
                info_url=str(entry.get("info_url", "")),
                upstream_file=str(entry.get("upstream_file", "")),
            )
            specs[spec.name] = spec

        _SPECS_CACHE = specs
        return specs


def get_operation_spec(name: str) -> OperationSpec:
    """Retrieve metadata specification for *name*."""
    specs = load_specs()
    try:
        return specs[name]
    except KeyError as exc:
        raise UnknownOperationError(f"unknown operation: {name}") from exc


def list_operation_specs() -> tuple[OperationSpec, ...]:
    """Retrieve all operation specifications sorted by name."""
    specs = load_specs()
    return tuple(specs[name] for name in sorted(specs))
