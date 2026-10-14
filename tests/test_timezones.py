"""Time zone handling must not depend on the host's zone database being present."""

from __future__ import annotations

import zoneinfo

import pytest

from pychef import OperationError, bake

FORMAT = "dddd Do MMMM YYYY HH:mm:ss Z z"


def convert(value: str, zone: str) -> str:
    args = ["Standard date and time", "DD/MM/YYYY HH:mm:ss", "UTC", FORMAT, zone]
    result = bake(value, [{"op": "Translate DateTime Format", "args": args}])
    assert isinstance(result, str)
    return result


@pytest.mark.parametrize(
    ("value", "zone", "expected"),
    [
        ("15/01/2024 12:00:00", "UTC", "Monday 15th January 2024 12:00:00 +00:00 UTC"),
        ("15/01/2024 12:00:00", "Europe/Berlin", "Monday 15th January 2024 13:00:00 +01:00 CET"),
        ("15/07/2024 12:00:00", "Europe/Berlin", "Monday 15th July 2024 14:00:00 +02:00 CEST"),
        ("15/01/2024 12:00:00", "US/Eastern", "Monday 15th January 2024 07:00:00 -05:00 EST"),
        ("15/07/2024 12:00:00", "US/Eastern", "Monday 15th July 2024 08:00:00 -04:00 EDT"),
        # Transition days: Berlin 2024-03-31 01:00 UTC, New York 2024-11-03 06:00 UTC
        ("31/03/2024 00:59:59", "Europe/Berlin", "Sunday 31st March 2024 01:59:59 +01:00 CET"),
        ("31/03/2024 01:00:00", "Europe/Berlin", "Sunday 31st March 2024 03:00:00 +02:00 CEST"),
        ("03/11/2024 05:59:59", "US/Eastern", "Sunday 3rd November 2024 01:59:59 -04:00 EDT"),
        ("03/11/2024 06:00:00", "US/Eastern", "Sunday 3rd November 2024 01:00:00 -05:00 EST"),
    ],
)
def test_offsets_and_daylight_saving(value: str, zone: str, expected: str) -> None:
    assert convert(value, zone) == expected


def test_unknown_zone_names_the_identifier() -> None:
    with pytest.raises(OperationError, match=r"unknown timezone: Mars/Olympus"):
        convert("15/01/2024 12:00:00", "Mars/Olympus")


def test_missing_database_gives_actionable_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    from pychef.operations import datetime_ops

    def no_database(key: str) -> object:
        raise zoneinfo.ZoneInfoNotFoundError(f"No time zone found with key {key}")

    monkeypatch.setattr(datetime_ops, "ZoneInfo", no_database)
    with pytest.raises(OperationError) as excinfo:
        convert("15/01/2024 12:00:00", "Europe/Berlin")
    assert "Europe/Berlin" in str(excinfo.value)
    assert "tzdata" in str(excinfo.value)


def test_zone_identifier_is_not_a_blanket_sanitizer_exemption() -> None:
    from pychef.recipe import _sanitize_error_message

    assert "secret-token-1" not in _sanitize_error_message(
        "bad value secret-token-1", ["secret-token-1"]
    )
    assert "Mars/Olympus" in _sanitize_error_message(
        "unknown timezone: Mars/Olympus", ["Mars/Olympus"]
    )
    # a shape that is not a plain zone identifier stays redacted
    assert "pa ss word" not in _sanitize_error_message(
        "unknown timezone: pa ss word", ["pa ss word"]
    )


def test_tzdata_is_declared_for_windows_only() -> None:
    from importlib.metadata import requires

    declared = requires("cyberchef-py") or []
    assert declared, "tzdata marker missing from package metadata"
    assert all(r.startswith("tzdata") and "win" in r.lower() for r in declared)
