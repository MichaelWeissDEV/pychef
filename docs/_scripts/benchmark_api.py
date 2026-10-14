#!/usr/bin/env python3
"""Micro-benchmarks for API-layer overhead (not algorithm throughput).

Usage: ``python docs/_scripts/benchmark_api.py [--src PATH] [--repeat N]``

``--src`` puts another checkout's ``src`` directory first on ``sys.path`` so that a
baseline commit can be measured with the same script. Every measurement is the
median of ``--repeat`` runs after a warm-up; import costs are measured in fresh
interpreters. Entries that do not exist in the measured version print ``n/a``.
"""

from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
import time
from collections.abc import Callable


def import_cost(src: str | None, statement: str, repeat: int) -> tuple[float, int, float]:
    prefix = f"import sys; sys.path.insert(0, {src!r});" if src else ""
    code = (
        prefix
        + "import time,resource;t=time.perf_counter();"
        + statement
        + ";dt=(time.perf_counter()-t)*1000;"
        "n=len([m for m in sys.modules if m.startswith('pychef')]);"
        "print(dt,n,resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)"
    )
    runs = []
    for _ in range(repeat):
        try:
            out = subprocess.run(
                [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
            ).stdout.split()
        except subprocess.CalledProcessError:
            return (float("nan"), 0, float("nan"))
        runs.append((float(out[0]), int(out[1]), float(out[2])))
    rss_divisor = 1e6 if sys.platform == "darwin" else 1e3  # ru_maxrss: bytes vs KiB
    return (
        statistics.median(r[0] for r in runs),
        runs[0][1],
        statistics.median(r[2] for r in runs) / rss_divisor,
    )


def per_call_us(function: Callable[[], object], repeat: int, number: int = 2000) -> float:
    for _ in range(100):  # warm-up
        function()
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        for _ in range(number):
            function()
        samples.append((time.perf_counter() - start) / number * 1e6)
    return statistics.median(samples)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src")
    parser.add_argument("--repeat", type=int, default=15)
    options = parser.parse_args()
    if options.src:
        sys.path.insert(0, options.src)

    print(f"python {sys.version.split()[0]} on {sys.platform}; median of {options.repeat} runs")
    for label, statement in [
        ("import pychef", "import pychef"),
        ("from pychef.ops import from_hex", "from pychef.ops import from_hex"),
        ("import pychef + first bake", "import pychef; pychef.bake('41', ['From Hex'])"),
    ]:
        ms, modules, rss = import_cost(options.src, statement, options.repeat)
        print(f"{label:38s} {ms:8.1f} ms  {modules:3d} pychef modules  {rss:6.1f} MB max RSS")

    import pychef

    steps = ["From Hex", "To Base64"]
    pipeline = pychef.Pipeline().from_hex().to_base64()
    recipe = pychef.Recipe(steps)
    chef = pychef.Chef()
    rows: list[tuple[str, Callable[[], object]]] = [
        ("bake(...) two steps", lambda: pychef.bake("414243", steps)),
        ("Recipe(...) construction", lambda: pychef.Recipe(steps)),
        ("Chef.bake(prebuilt Recipe)", lambda: chef.bake("414243", recipe)),
        ("Pipeline() construction (2 steps)", lambda: pychef.Pipeline().from_hex().to_base64()),
        ("Pipeline call (reused)", lambda: pipeline("414243")),
    ]
    try:
        from pychef.ops import from_hex, to_base64

        rows.append(("ops: to_base64(from_hex(...))", lambda: to_base64(from_hex("414243"))))
    except ImportError:
        pass
    for label, function in rows:
        print(f"{label:38s} {per_call_us(function, options.repeat):8.1f} us/call")

    worker_runs = []
    for _ in range(5):
        start = time.perf_counter()
        pychef.bake_isolated("414243", steps, timeout=60)
        worker_runs.append((time.perf_counter() - start) * 1000)
    print(f"{'bake_isolated (process start)':38s} {statistics.median(worker_runs):8.1f} ms/call")


if __name__ == "__main__":
    main()
