#!/usr/bin/env python3
"""Type-check ``tests/typing_examples/ops_usage.txt`` against an *installed wheel*.

A fresh virtual environment receives the given wheel and nothing else, so the
check proves that ``py.typed`` and the annotations ship in the distribution and
that no repository source is reachable.

Usage: ``python tests/check_wheel_typing.py dist/cyberchef_py-*.whl``
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "tests" / "typing_examples" / "ops_usage.txt"
EXPECTED_ERROR_LINES = 2  # the two intentional misuse lines at the end of the example


def main(wheel: str) -> int:
    uv = shutil.which("uv")
    ty = shutil.which("ty")
    if uv is None or ty is None:
        print("uv and ty must be on PATH (run through `uv run`)", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        venv = work / "venv"
        subprocess.run([uv, "venv", "--quiet", str(venv)], check=True)
        interpreter = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run(
            [uv, "pip", "install", "--quiet", "--python", str(interpreter), wheel], check=True
        )
        subprocess.run([uv, "pip", "check", "--python", str(interpreter)], check=True)
        source = work / "example.py"
        shutil.copy(EXAMPLE, source)
        result = subprocess.run(
            [
                ty,
                "check",
                "--python",
                str(venv),
                "--python-version",
                "3.12",
                "--output-format",
                "concise",
                str(source),
            ],
            cwd=work,
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout + result.stderr
        print(output)
        last = len(source.read_text().splitlines())
        flagged = {int(m.group(1)) for m in re.finditer(r"example\.py:(\d+):\d+: error", output)}
        if flagged != {last - 1, last}:
            print(f"expected errors only on lines {last - 1} and {last}", file=sys.stderr)
            return 1
    print("installed-wheel typing check passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
