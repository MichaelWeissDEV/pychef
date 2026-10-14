"""Every example script must run unchanged in a fresh interpreter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES = sorted((Path(__file__).resolve().parents[1] / "examples").glob("*.py"))


def test_examples_are_present() -> None:
    assert {path.stem for path in EXAMPLES} >= {
        "quickstart",
        "direct_operations",
        "recipes",
        "pipelines",
        "execution_policy",
        "worker_execution",
    }


@pytest.mark.parametrize("script", EXAMPLES, ids=lambda path: path.stem)
def test_example_runs(script: Path, tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(script)],
        cwd=tmp_path,  # no access to repository-relative paths
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
