"""Configure resource and network limits."""

from pychef import (
    Chef,
    ExecutionLimitError,
    ExecutionPolicy,
    NetworkPolicy,
    OperationPermissionError,
    bake,
)


def main() -> None:
    # The default policy is ExecutionPolicy.safe(): bounded resources, no network.
    try:
        bake("", [{"op": "HTTP request", "args": ["GET", "http://127.0.0.1:9/"]}])
    except OperationPermissionError as error:
        print(f"Network denied by default: {error.safe_message}")

    # Tighten limits for untrusted data ...
    strict = ExecutionPolicy.untrusted()
    chef = Chef(policy=strict)
    assert chef.bake("4142", ["From Hex"]) == b"AB"

    # ... or set individual limits. `None` disables a limit explicitly.
    small = ExecutionPolicy(max_input_bytes=8, max_steps=4)
    try:
        bake("41" * 16, ["From Hex"], policy=small)
    except ExecutionLimitError as error:
        print(f"Limit hit: {error.limit}")

    # Network access must be granted explicitly and can be narrowed to hosts.
    allow_one_host = ExecutionPolicy(
        network=NetworkPolicy(mode="public_only", allowed_hosts=("example.com",))
    )
    assert allow_one_host.allow_network
    assert not ExecutionPolicy.safe().allow_network


if __name__ == "__main__":
    main()
