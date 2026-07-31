"""Pure-Python CyberChef-compatible data transformations."""

# Importing the package registers all built-in operations.
from . import operations as _operations  # noqa: F401
from .compatibility import CompatibilityReport, compatibility_report
from .errors import OperationError, PyChefError, RecipeError, UnknownOperationError
from .recipe import Chef, Recipe, bake
from .registry import Operation, OperationRegistry, registry
from .types import BakeResult, Data, RecipeConfig, RecipeStep

__all__ = [
    "BakeResult",
    "Chef",
    "CompatibilityReport",
    "Data",
    "Operation",
    "OperationError",
    "OperationRegistry",
    "PyChefError",
    "Recipe",
    "RecipeConfig",
    "RecipeError",
    "RecipeStep",
    "UnknownOperationError",
    "bake",
    "compatibility_report",
    "list_operations",
    "registry",
]

__version__ = "0.1.0"


def list_operations() -> tuple[str, ...]:
    """Return every registered operation name in stable alphabetical order."""
    return registry.names()
