"""Compose reusable pipelines with Python callables and branches."""

from pychef import Pipeline


def main() -> None:
    # Pipelines are immutable: every method returns a new pipeline.
    decoder = Pipeline().from_hex().xor(b"\x42").decode()
    assert decoder("0a272e2e2d") == "Hello"

    # `|` joins pipelines; `apply` adds trusted Python functions.
    shout = decoder | Pipeline().apply(str.upper, name="upper")
    assert shout("0a272e2e2d") == "HELLO"

    # `concat` runs several branches on the same input and joins the results.
    both = Pipeline().concat(
        Pipeline().to_hex(),
        Pipeline().to_base64(),
        separator=" | ",
    )
    assert both("Hi") == "4869 | SGk="

    # Piping a value into a pipeline also works.
    assert "Hi" | Pipeline().to_base64() == "SGk="

    # `trace` keeps every intermediate value for debugging.
    for entry in decoder.trace("0a272e2e2d"):
        print(f"{entry.name}: {entry.input!r} -> {entry.output!r}")
    print(f"Pipeline stages: {decoder.steps}")


if __name__ == "__main__":
    main()
