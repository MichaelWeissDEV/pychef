"""Transform a finite batch with one shared execution budget."""

from pychef import ExecutionLimitError, ExecutionPolicy, Pipeline


def main() -> None:
    decode = Pipeline().from_hex().decode()
    words = ["48656c6c6f", "576f726c64", "5079436865", "66"]

    # `transform_many` materializes every result (a tuple), keeping input order.
    assert decode.transform_many(words) == ("Hello", "World", "PyChe", "f")

    # All items share ONE budget (steps, deadline, ...): a batch of 4 items x 2 stages
    # needs 8 steps, so a smaller budget stops the batch part-way through.
    try:
        decode.transform_many(words, policy=ExecutionPolicy(max_steps=5))
    except ExecutionLimitError as error:
        print(f"Budget exhausted as expected: limit={error.limit}")
    else:
        raise AssertionError("expected the shared step budget to be exceeded")

    # Use a fresh call per item for independent budgets.
    independent = [decode(word, policy=ExecutionPolicy(max_steps=2)) for word in words]
    assert independent == ["Hello", "World", "PyChe", "f"]
    print(f"Decoded {len(independent)} items")


if __name__ == "__main__":
    main()
