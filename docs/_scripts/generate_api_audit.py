"""Generate the symbol table of ``docs/dev/public-api-audit.md``.

Usage: ``uv run python docs/_scripts/generate_api_audit.py`` prints Markdown tables
for ``pychef.__all__`` and ``pychef.ops.__all__``. ``Typed`` reports whether every
parameter and the return value of a callable carry annotations; ``Docstring``
whether the object has its own docstring; ``In docs`` whether the name appears in
the hand-written pages under ``docs/`` (excluding generated operation pages).
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pychef
import pychef.ops as ops

DOCS = Path(__file__).resolve().parents[1]
CORPUS = "\n".join(
    path.read_text(encoding="utf-8")
    for path in DOCS.rglob("*.rst")
    if "operations" not in path.relative_to(DOCS).parts
)

CATEGORIES = {
    "Core API": {"bake", "Recipe", "RecipeConfig", "RecipeStep", "BakeResult", "TraceStep"},
    "Fluent API": {"Pipeline", "PipelineTrace"},
    "Engine": {"Chef", "ExecutionContext", "PolicyDecision", "normalize_host", "registry"},
    "Policy": {"ExecutionPolicy", "NetworkPolicy"},
    "Isolation": {"IsolatedWorker", "bake_isolated"},
    "Registry": {"Operation", "OperationRegistry", "list_operations"},
    "Metadata": {
        "OperationArgSpec",
        "OperationSpec",
        "get_operation_spec",
        "list_operation_specs",
        "CompatibilityReport",
        "compatibility_report",
    },
    "Types": {"Data"},
}


AUTOMODULES = set(re.findall(r"^\.\. automodule:: (\S+)", CORPUS, flags=re.M))


def module_of(name: str, obj: object, namespace: object) -> str:
    module = getattr(obj, "__module__", None)
    if module in {None, "types", "typing", "collections.abc"}:
        return "pychef.types" if hasattr(__import__("pychef.types").types, name) else "?"
    return module


def category(name: str, obj: object) -> str:
    for label, names in CATEGORIES.items():
        if name in names:
            return label
    if isinstance(obj, type) and issubclass(obj, BaseException):
        return "Errors"
    module = getattr(obj, "__module__", "")
    if module.startswith("pychef.ops"):
        return "Direct operations"
    if module == "pychef.packets":
        return "Packets"
    if module == "pychef.ctf":
        return "CTF helpers"
    return "Other"


def typed(obj: object) -> str:
    if inspect.isclass(obj):
        methods = [
            member
            for member_name, member in inspect.getmembers(obj, inspect.isfunction)
            if not member_name.startswith("_") and member.__qualname__.startswith(obj.__name__)
        ]
        if not methods:
            return "n/a"
        complete = all(_complete(method) for method in methods)
        return "yes" if complete else "partial"
    if callable(obj) and inspect.isroutine(obj):
        return "yes" if _complete(obj) else "partial"
    return "n/a"


def _complete(function: object) -> bool:
    try:
        signature = inspect.signature(cast("Callable[..., Any]", function))
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.name in {"self", "cls"}:
            continue
        if parameter.annotation is inspect.Parameter.empty:
            return False
    return signature.return_annotation is not inspect.Signature.empty


def has_doc(obj: object) -> str:
    if not (inspect.isroutine(obj) or inspect.isclass(obj)):
        return "n/a"
    own = obj.__dict__.get("__doc__") if inspect.isclass(obj) else getattr(obj, "__doc__", None)
    return "yes" if own and own.strip() else "no"


def table(names: list[str], namespace: object, stability: str) -> str:
    rows = [
        "| Public Symbol | Module | Category | Stability | Typed | Docstring | In docs |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in sorted(names, key=str.lower):
        obj = getattr(namespace, name)
        module = module_of(name, obj, namespace)
        mentioned = re.search(rf"(?<![\w.]){re.escape(name)}(?!\w)", CORPUS) is not None
        public_module = module.replace("._engine", "")
        covered = (
            module in AUTOMODULES
            or public_module in AUTOMODULES
            or ("pychef.ops" in AUTOMODULES and module.startswith("pychef.ops"))
        )
        documented = "yes" if mentioned or covered else "no"
        rows.append(
            f"| `{name}` | `{module}` | {category(name, obj)} | {stability} | "
            f"{typed(obj)} | {has_doc(obj)} | {documented} |"
        )
    return "\n".join(rows)


if __name__ == "__main__":
    print("## `pychef.__all__`\n")
    print(table(list(pychef.__all__), pychef, "existing"))
    print("\n## `pychef.ops.__all__`\n")
    print(table(list(ops.__all__), ops, "new"))
