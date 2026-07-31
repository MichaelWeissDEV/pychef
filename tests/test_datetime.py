"""Official CyberChef date/time vectors."""

from __future__ import annotations

import re
import uuid

from pychef import bake


def test_filetime_official_vectors() -> None:
    assert (
        bake(
            "129207366395297693",
            [{"op": "Windows Filetime to UNIX Timestamp", "args": ["Nanoseconds (ns)", "Decimal"]}],
        )
        == "1276263039529769300"
    )
    assert (
        bake(
            "1276263039529769300",
            [{"op": "UNIX Timestamp to Windows Filetime", "args": ["Nanoseconds (ns)", "Decimal"]}],
        )
        == "129207366395297693"
    )


def test_datetime_delta_official_vectors() -> None:
    assert (
        bake(
            "20/02/2024 13:36:00",
            [
                {
                    "op": "DateTime Delta",
                    "args": ["Standard date and time", "DD/MM/YYYY HH:mm:ss", "Add", 0, 0, 1, 0],
                }
            ],
        )
        == "20/02/2024 13:37:00"
    )
    assert (
        bake(
            "20/02/2024 14:37:00",
            [
                {
                    "op": "DateTime Delta",
                    "args": [
                        "Standard date and time",
                        "DD/MM/YYYY HH:mm:ss",
                        "Subtract",
                        0,
                        1,
                        0,
                        0,
                    ],
                }
            ],
        )
        == "20/02/2024 13:37:00"
    )


def test_translate_datetime_format_official_vectors() -> None:
    args = [
        "Standard date and time",
        "DD/MM/YYYY HH:mm:ss",
        "UTC",
        "dddd Do MMMM YYYY HH:mm:ss Z z",
        "UTC",
    ]
    assert (
        bake("01/04/1999 22:33:01", [{"op": "Translate DateTime Format", "args": args}])
        == "Thursday 1st April 1999 22:33:01 +00:00 UTC"
    )
    assert bake("1234567890", [{"op": "Translate DateTime Format", "args": args}]) == (
        "Invalid format."
    )
    eastern_args = [*args[:4], "US/Eastern"]
    assert (
        bake(
            "01/04/1999 22:33:01",
            [{"op": "Translate DateTime Format", "args": eastern_args}],
        )
        == "Thursday 1st April 1999 17:33:01 -05:00 EST"
    )
    automatic_args = [
        "Automatic",
        "",
        "UTC",
        "dddd Do MMMM YYYY HH:mm:ss Z z",
        "UTC",
    ]
    assert (
        bake(
            "1999-04-01 22:33:01",
            [{"op": "Translate DateTime Format", "args": automatic_args}],
        )
        == "Thursday 1st April 1999 22:33:01 +00:00 UTC"
    )


def test_parse_datetime_official_vector() -> None:
    expected = """Date: Friday 6th July 2001
Time: 01:59:30
Period: AM
Timezone: UTC
UTC offset: +0000

Daylight Saving Time: false
Leap year: false
Days in this month: 31

Day of year: 187
Week number: 27
Quarter: 3"""
    assert (
        bake(
            "06/07/2001 01:59:30",
            [{"op": "Parse DateTime", "args": ["Standard", "DD/MM/YYYY HH:mm:ss", "UTC"]}],
        )
        == expected
    )


def test_unix_timestamp_round_trip() -> None:
    rendered = bake("0", [{"op": "From UNIX Timestamp", "args": ["Seconds (s)"]}])
    assert rendered == "Thu 1 January 1970 00:00:00 UTC"
    assert (
        bake(
            "1970-01-01T00:00:01+00:00",
            [{"op": "To UNIX Timestamp", "args": ["Seconds (s)", True, False]}],
        )
        == "1"
    )


def test_uuid_generation_and_analysis() -> None:
    namespace = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    generated = bake("python.org", [{"op": "Generate UUID", "args": ["v5", namespace]}])
    assert generated == str(uuid.uuid5(uuid.UUID(namespace), "python.org"))
    analysis = bake(generated, [{"op": "Analyse UUID", "args": [True]}])
    assert isinstance(analysis, str)
    assert "Version: 5" in analysis
    random_uuid = bake("", [{"op": "Generate UUID", "args": ["v4", namespace]}])
    assert isinstance(random_uuid, str)
    assert re.fullmatch(r"[0-9a-f-]{36}", random_uuid)


def test_objectid_and_get_time() -> None:
    assert (
        bake("000000000000000000000000", ["Parse ObjectID timestamp"])
        == "Thu 01 January 1970 00:00:00 UTC"
    )
    assert int(bake("", [{"op": "Get Time", "args": ["Seconds (s)"]}])) > 1_700_000_000
