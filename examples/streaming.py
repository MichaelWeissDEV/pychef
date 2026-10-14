"""Process an unbounded iterable lazily with `iter_transform`."""

from collections.abc import Iterator

from pychef import ExecutionPolicy, Pipeline


def produce_chunks() -> Iterator[str]:
    for number in range(5):
        yield f"{number:02x}"  # a generator: nothing is buffered up front


def main() -> None:
    to_text = Pipeline().from_hex().to_base64()
    # The whole stream shares one policy; lift step and time limits for long streams.
    long_running = ExecutionPolicy(max_steps=None, cooperative_deadline_seconds=None)
    stream = to_text.iter_transform(produce_chunks(), policy=long_running)
    first = next(stream)  # only the first chunk has been produced and transformed
    assert first == "AA=="
    remaining = list(stream)
    assert remaining == ["AQ==", "Ag==", "Aw==", "BA=="]
    print(f"Streamed {1 + len(remaining)} chunks lazily")


if __name__ == "__main__":
    main()
