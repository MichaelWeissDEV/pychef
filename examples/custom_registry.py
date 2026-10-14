"""Run recipes against a private OperationRegistry with one custom operation."""

from pychef import Chef, Data, Operation, OperationRegistry
from pychef.types import Args, to_text


def shout(value: Data, args: Args) -> Data:
    suffix = str(args[0]) if args else "!"
    return to_text(value).upper() + suffix


def main() -> None:
    private = OperationRegistry(manifest={})  # empty: built-in operations are not included
    private.register(Operation("Shout", shout, category="Examples"))

    chef = Chef(operation_registry=private)
    assert chef.bake("hello", [{"op": "Shout", "args": ["?!"]}]) == "HELLO?!"
    print(f"Registered operations: {private.names()}")


if __name__ == "__main__":
    main()
