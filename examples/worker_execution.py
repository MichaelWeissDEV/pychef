"""Run recipes in an isolated subprocess with a hard deadline."""

from pychef import ExecutionPolicy, ExecutionTimeoutError, IsolatedWorker, bake_isolated


def main() -> None:
    assert bake_isolated("414243", ["From Hex", "To Base64"], timeout=30) == "QUJD"

    # A worker enforces the deadline from outside the interpreter, so even a
    # stalled operation cannot block the calling process.
    with IsolatedWorker(timeout=30, policy=ExecutionPolicy.untrusted()) as worker:
        result = worker.run("68656c6c6f", ["From Hex", "To Base64"])
        print(f"{result.result!r} in {result.duration_ms:.0f} ms (including process start)")

    try:
        bake_isolated("41", ["From Hex"], timeout=1e-6)
    except ExecutionTimeoutError as error:
        print(f"Deadline enforced: {error}")


if __name__ == "__main__":  # required: workers use the "spawn" start method
    main()
