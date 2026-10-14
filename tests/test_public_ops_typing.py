"""Static typing checks for the public API, run with the project's type checker (ty)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "tests" / "typing_examples" / "ops_usage.txt"


@pytest.mark.skipif(shutil.which("ty") is None, reason="ty is not installed")
def test_public_api_types_check_against_source_tree(tmp_path: Path) -> None:
    """Fast variant against ``src/``. ``tests/check_wheel_typing.py`` checks a wheel."""
    source = tmp_path / "example.py"
    shutil.copy(EXAMPLE, source)
    result = subprocess.run(
        [
            "ty",
            "check",
            "--python-version",
            "3.12",  # typing.assert_type needs 3.11+; the package itself supports 3.10
            "--extra-search-path",
            str(ROOT / "src"),
            "--output-format",
            "concise",
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    output = result.stdout + result.stderr
    last = len(source.read_text().splitlines())
    flagged = {int(m.group(1)) for m in re.finditer(r"example\.py:(\d+):\d+: error", output)}
    assert flagged == {last - 1, last}, output


def test_py_typed_marker_ships_with_package() -> None:
    import pychef

    assert (Path(pychef.__file__).parent / "py.typed").is_file()
