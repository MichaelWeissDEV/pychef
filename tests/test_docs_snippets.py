"""Run the ``>>>`` examples embedded in the hand-written documentation pages."""

from __future__ import annotations

import doctest
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"
PAGES = [
    "getting-started",
    "choosing-an-api",
    "direct-operations",
    "cookbook",
    "execution-policies",
    "custom-registries",
    "tracing",
    "recipes",
]


@pytest.mark.parametrize("page", PAGES)
def test_documentation_page_examples(page: str) -> None:
    path = DOCS / f"{page}.rst"
    if not path.exists():  # the sdist ships docs, wheels do not
        pytest.skip("documentation sources are not available")
    result = doctest.testfile(
        str(path),
        module_relative=False,
        optionflags=doctest.ELLIPSIS,
        verbose=False,
        encoding="utf-8",
    )
    assert result.attempted > 0
    assert result.failed == 0
