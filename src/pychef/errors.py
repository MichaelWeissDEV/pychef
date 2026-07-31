"""PyChef exception hierarchy."""


class PyChefError(Exception):
    """Base class for all public PyChef errors."""


class UnknownOperationError(PyChefError, LookupError):
    """Raised when a recipe names an operation that is not registered."""


class OperationError(PyChefError):
    """Raised when an operation cannot transform its input."""

    def __init__(self, operation: str, message: str) -> None:
        self.operation = operation
        self.message = message
        super().__init__(f"{operation}: {message}")


class RecipeError(PyChefError):
    """Raised when a recipe configuration is malformed."""
