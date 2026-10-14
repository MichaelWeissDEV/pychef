"""PyChef exception hierarchy.

Every error exposes structured, machine-readable fields (``error_code``,
``operation_name``, ``step_index``, ``branch_path``, ``execution_id``,
``message`` and ``cause``) so that CLIs, editors and servers can render
diagnostics without parsing text.  Messages never include operation arguments
such as keys or passwords; the original exception is preserved through normal
exception chaining (``__cause__``).
"""

from __future__ import annotations

from typing import Any


class PyChefError(Exception):
    """Base class for all public PyChef errors."""

    default_error_code = "pychef_error"

    def __init__(
        self,
        message: str = "",
        *,
        error_code: str | None = None,
        operation_name: str | None = None,
        step_index: int | None = None,
        branch_path: tuple[int, ...] | None = None,
        execution_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.default_error_code
        self.operation_name = operation_name
        self.step_index = step_index
        self.branch_path = branch_path
        self.execution_id = execution_id

    @property
    def cause(self) -> BaseException | None:
        """The chained original exception, if any."""
        return self.__cause__ or self.__context__

    @property
    def safe_message(self) -> str:
        """Redacted, public-safe error message."""
        return self.message

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable description (no traceback, no arguments)."""
        cause = self.cause
        return {
            "error_code": self.error_code,
            "type": type(self).__name__,
            "message": self.message,
            "safe_message": self.safe_message,
            "operation_name": self.operation_name,
            "step_index": self.step_index,
            "branch_path": list(self.branch_path) if self.branch_path is not None else None,
            "execution_id": self.execution_id,
            "cause": type(cause).__name__ if cause is not None else None,
        }


class UnknownOperationError(PyChefError, LookupError):
    """Raised when a recipe names an operation that is not registered."""

    default_error_code = "unknown_operation"


class OperationError(PyChefError):
    """Raised when an operation cannot transform its input."""

    default_error_code = "operation_failed"

    def __init__(self, operation: str, message: str, **context: Any) -> None:
        context.setdefault("operation_name", operation)
        super().__init__(f"{operation}: {message}", **context)
        self.operation = operation
        self.message = message

    def __reduce__(self) -> tuple[Any, ...]:
        return (self.__class__, (self.operation, self.message), self.__dict__)


class RecipeError(PyChefError):
    """Raised when a recipe configuration is malformed."""

    default_error_code = "invalid_recipe"


class InvalidOperationArgumentsError(OperationError, ValueError):
    """Raised when operation or flow-control arguments are invalid."""

    default_error_code = "invalid_arguments"


class OperationPermissionError(OperationError, PermissionError):
    """Raised when the active :class:`ExecutionPolicy` forbids an operation."""

    default_error_code = "permission_denied"


class ExecutionLimitError(PyChefError):
    """Raised when a cooperative resource limit of the execution policy is exceeded."""

    default_error_code = "limit_exceeded"

    def __init__(self, limit: str, message: str, **context: Any) -> None:
        super().__init__(message, **context)
        self.limit = limit

    def __reduce__(self) -> tuple[Any, ...]:
        return (self.__class__, (self.limit, self.message), self.__dict__)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["limit"] = self.limit
        return data


class ExecutionTimeoutError(ExecutionLimitError, TimeoutError):
    """Raised when the cooperative deadline passed between two steps.

    This is *not* a hard timeout: a single operation that blocks is never
    interrupted.  See ``docs/security.md``.
    """

    default_error_code = "deadline_exceeded"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__("cooperative_deadline_seconds", message, **context)

    def __reduce__(self) -> tuple[Any, ...]:
        return (self.__class__, (self.message,), self.__dict__)
