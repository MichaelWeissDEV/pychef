"""Release metadata invariants."""

from __future__ import annotations

from importlib.metadata import metadata, version

import pychef


def test_distribution_metadata_matches_runtime_package() -> None:
    package = metadata("cyberchef-py")
    assert package["Name"] == "cyberchef-py"
    assert package["Requires-Python"] == ">=3.10"
    requirements = package.get_all("Requires-Dist")
    # The only runtime dependency is the Windows-only IANA time zone database.
    assert requirements == ["tzdata; platform_system == 'Windows'"]
    assert pychef.__version__ == version("cyberchef-py")
