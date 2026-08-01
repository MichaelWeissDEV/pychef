"""Release metadata invariants."""

from __future__ import annotations

from importlib.metadata import metadata, version

import pychef


def test_distribution_metadata_matches_runtime_package() -> None:
    package = metadata("py-chef")
    assert package["Name"] == "py-chef"
    assert package["Requires-Python"] == ">=3.10"
    requirements = package.get_all("Requires-Dist")
    assert requirements is None or requirements == []
    assert pychef.__version__ == version("py-chef")
