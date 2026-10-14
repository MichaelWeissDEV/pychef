"""Handle PyChef errors without leaking input data."""

from pychef import (
    ExecutionLimitError,
    ExecutionPolicy,
    PyChefError,
    RecipeError,
    UnknownOperationError,
    bake,
)


def main() -> None:
    try:
        bake("abc", ["No Such Operation"])
    except UnknownOperationError as error:
        print(f"Unknown operation: {error}")

    try:
        bake("abc", [{"args": []}])
    except RecipeError as error:
        print(f"Invalid recipe: {error}")

    try:
        bake("a" * 100, ["To Hex"], policy=ExecutionPolicy(max_input_bytes=10))
    except ExecutionLimitError as error:
        print(f"Limit {error.limit} exceeded: {error.safe_message}")
        print(f"Structured: {sorted(error.to_dict())}")

    # Every library error derives from PyChefError.
    try:
        bake("abc", ["No Such Operation"])
    except PyChefError as error:
        assert isinstance(error, LookupError)


if __name__ == "__main__":
    main()
