"""Pinned CyberChef operation-inventory checks."""

from __future__ import annotations

from pychef import compatibility_report, list_operations
from pychef.compatibility import TARGET_CYBERCHEF_COMMIT, TARGET_CYBERCHEF_VERSION


def test_pinned_upstream_inventory_is_explicit() -> None:
    report = compatibility_report()
    assert report.target_version == TARGET_CYBERCHEF_VERSION == "11.3.0"
    assert report.target_commit == TARGET_CYBERCHEF_COMMIT
    assert report.upstream_count == 502
    assert len(report.implemented) == len(list_operations()) == 337
    assert len(report.missing) == 165
    assert report.unexpected == ()
    assert report.coverage == 337 / 502
    assert not report.complete
