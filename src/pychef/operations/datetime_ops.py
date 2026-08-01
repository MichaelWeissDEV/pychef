"""Timestamp, UUID, and date/time operations."""

from __future__ import annotations

import re
import time
import uuid
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg, require_int

_FILETIME_EPOCH = 116_444_736_000_000_000
_UNITS = {
    "Seconds (s)": 1,
    "Milliseconds (ms)": 1_000,
    "Microseconds (μs)": 1_000_000,
    "Nanoseconds (ns)": 1_000_000_000,
}


@implementation("Windows Filetime to UNIX Timestamp", category="Date / Time")
def windows_filetime_to_unix(value: Data, args: Args) -> str:
    output_units = str(arg(args, 0, "Seconds (s)"))
    input_format = str(arg(args, 1, "Decimal"))
    text = to_text(value).strip()
    if input_format == "Hex (little endian)":
        filetime = int.from_bytes(bytes.fromhex(text.removeprefix("0x")), "little")
    elif input_format == "Hex (big endian)":
        filetime = int(text, 16)
    else:
        filetime = int(text)
    nanoseconds = (filetime - _FILETIME_EPOCH) * 100
    return str(nanoseconds * _UNITS[output_units] // 1_000_000_000)


@implementation("UNIX Timestamp to Windows Filetime", category="Date / Time")
def unix_to_windows_filetime(value: Data, args: Args) -> str:
    input_units = str(arg(args, 0, "Seconds (s)"))
    output_format = str(arg(args, 1, "Decimal"))
    timestamp = int(to_text(value).strip())
    filetime = timestamp * 10_000_000 // _UNITS[input_units] + _FILETIME_EPOCH
    if output_format == "Hex (little endian)":
        return filetime.to_bytes(8, "little").hex()
    if output_format == "Hex (big endian)":
        return f"{filetime:016x}"
    return str(filetime)


def _timestamp_seconds(text: str, units: str) -> float:
    return float(text) / _UNITS[units]


@implementation("From UNIX Timestamp", category="Date / Time")
def from_unix_timestamp(value: Data, args: Args) -> str:
    units = str(arg(args, 0, "Seconds (s)"))
    instant = datetime.fromtimestamp(_timestamp_seconds(to_text(value), units), tz=timezone.utc)
    months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    milliseconds = f".{instant.microsecond // 1000:03d}" if units != "Seconds (s)" else ""
    return (
        f"{instant.strftime('%a')} {instant.day} {months[instant.month - 1]} "
        f"{instant.year} {instant:%H:%M:%S}{milliseconds} UTC"
    )


def _parse_datetime(text: str, utc: bool) -> datetime:
    normalized = text.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        formats = (
            "%a %d %B %Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d",
        )
        for date_format in formats:
            try:
                parsed = datetime.strptime(normalized, date_format)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unable to parse datetime: {text}") from None
    if parsed.tzinfo is None and utc:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@implementation("To UNIX Timestamp", category="Date / Time")
def to_unix_timestamp(value: Data, args: Args) -> str:
    units = str(arg(args, 0, "Seconds (s)"))
    treat_as_utc = bool(arg(args, 1, True))
    show_datetime = bool(arg(args, 2, True))
    parsed = _parse_datetime(to_text(value), treat_as_utc)
    multiplier = _UNITS[units]
    timestamp = int(parsed.timestamp() * multiplier)
    if not show_datetime:
        return str(timestamp)
    utc = parsed.astimezone(timezone.utc)
    months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    return (
        f"{timestamp} ({utc.strftime('%a')} {utc.day} {months[utc.month - 1]} "
        f"{utc.year} {utc:%H:%M:%S} UTC)"
    )


def _moment_format_to_strptime(format_string: str) -> str:
    tokens = {
        "YYYY": "%Y",
        "YY": "%y",
        "MMMM": "%B",
        "MMM": "%b",
        "MM": "%m",
        "DD": "%d",
        "HH": "%H",
        "hh": "%I",
        "mm": "%M",
        "ss": "%S",
        "A": "%p",
        "Z": "%z",
    }
    pattern = re.compile("|".join(sorted(map(re.escape, tokens), key=len, reverse=True)))
    return pattern.sub(lambda match: tokens[match.group()], format_string)


def _ordinal(value: int) -> str:
    suffix = "th" if 10 <= value % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(value % 10, "th")
    return f"{value}{suffix}"


def _moment_render(value: datetime, format_string: str) -> str:
    tokens = {
        "YYYY": f"{value.year:04d}",
        "YY": f"{value.year % 100:02d}",
        "MMMM": value.strftime("%B"),
        "MMM": value.strftime("%b"),
        "MM": f"{value.month:02d}",
        "M": str(value.month),
        "dddd": value.strftime("%A"),
        "ddd": value.strftime("%a"),
        "Do": _ordinal(value.day),
        "DD": f"{value.day:02d}",
        "D": str(value.day),
        "HH": f"{value.hour:02d}",
        "H": str(value.hour),
        "hh": value.strftime("%I"),
        "h": str(int(value.strftime("%I"))),
        "mm": f"{value.minute:02d}",
        "m": str(value.minute),
        "ss": f"{value.second:02d}",
        "s": str(value.second),
        "A": value.strftime("%p"),
        "a": value.strftime("%p").lower(),
        "ZZ": value.strftime("%z"),
        "Z": value.strftime("%z")[:3] + ":" + value.strftime("%z")[3:],
        "z": value.tzname() or "UTC",
    }
    pattern = re.compile("|".join(sorted(map(re.escape, tokens), key=len, reverse=True)))
    normalized_format = format_string.replace("<", "").replace(">", "")
    return pattern.sub(lambda match: tokens[match.group()], normalized_format)


def _zone(name: str) -> timezone | ZoneInfo:
    if name == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {name}") from exc


def _parse_moment(value: str, format_string: str, zone_name: str) -> datetime:
    if format_string:
        parsed = datetime.strptime(value, _moment_format_to_strptime(format_string))
    else:
        parsed = _parse_datetime(value, True)
    return parsed.replace(tzinfo=_zone(zone_name)) if parsed.tzinfo is None else parsed


@implementation("DateTime Delta", category="Date / Time")
def datetime_delta(value: Data, args: Args) -> str:
    custom_format = str(arg(args, 1, "DD/MM/YYYY HH:mm:ss"))
    direction = -1 if str(arg(args, 2, "Add")) == "Subtract" else 1
    days = require_int(arg(args, 3, 0))
    hours = require_int(arg(args, 4, 0))
    minutes = require_int(arg(args, 5, 0))
    seconds = require_int(arg(args, 6, 0))
    date_format = _moment_format_to_strptime(custom_format)
    parsed = datetime.strptime(to_text(value), date_format)
    result = parsed + direction * timedelta(
        days=days, hours=hours, minutes=minutes, seconds=seconds
    )
    return result.strftime(date_format)


@implementation("Translate DateTime Format", category="Date / Time")
def translate_datetime_format(value: Data, args: Args) -> str:
    input_format = str(arg(args, 1, "DD/MM/YYYY HH:mm:ss"))
    input_zone = str(arg(args, 2, "UTC"))
    output_format = str(arg(args, 3, "dddd Do MMMM YYYY HH:mm:ss Z z"))
    output_zone = str(arg(args, 4, "UTC"))
    try:
        parsed = _parse_moment(to_text(value), input_format, input_zone)
    except ValueError:
        return "Invalid format."
    return _moment_render(parsed.astimezone(_zone(output_zone)), output_format)


@implementation("Parse DateTime", category="Date / Time")
def parse_datetime(value: Data, args: Args) -> str:
    input_format = str(arg(args, 1, "DD/MM/YYYY HH:mm:ss"))
    input_zone = str(arg(args, 2, "UTC"))
    try:
        parsed = _parse_moment(to_text(value), input_format, input_zone)
    except ValueError:
        return "Invalid format."
    day_of_year = parsed.timetuple().tm_yday
    week = int(parsed.strftime("%U")) + 1
    date = f"{parsed.strftime('%A')} {_ordinal(parsed.day)} {parsed.strftime('%B')} {parsed.year}"
    leap_year = parsed.year % 4 == 0 and (parsed.year % 100 != 0 or parsed.year % 400 == 0)
    quarter = (parsed.month - 1) // 3 + 1
    return (
        f"Date: {date}"
        f"\nTime: {parsed:%H:%M:%S}\nPeriod: {parsed:%p}\nTimezone: {parsed.tzname() or 'UTC'}"
        f"\nUTC offset: {parsed:%z}\n\nDaylight Saving Time: "
        f"{str(bool(parsed.dst())).lower()}\nLeap year: "
        f"{str(leap_year).lower()}"
        f"\nDays in this month: {monthrange(parsed.year, parsed.month)[1]}"
        f"\n\nDay of year: {day_of_year}\nWeek number: {week}\nQuarter: {quarter}"
    )


@implementation("Get Time", category="Date / Time")
def get_time(_value: Data, args: Args) -> str:
    units = str(arg(args, 0, "Milliseconds (ms)"))
    return str(round(time.time() * _UNITS[units]))


@implementation("Generate UUID", category="Date / Time")
def generate_uuid(value: Data, args: Args) -> str:
    version = str(arg(args, 0, "v4"))
    namespace = uuid.UUID(str(arg(args, 1, "1b671a64-40d5-491e-99b0-da01ff1f3341")))
    if version == "v1":
        return str(uuid.uuid1())
    if version == "v3":
        return str(uuid.uuid3(namespace, to_text(value)))
    if version == "v5":
        return str(uuid.uuid5(namespace, to_text(value)))
    if version == "v7":
        milliseconds = int(time.time() * 1000)
        random_bits = uuid.uuid4().int & ((1 << 74) - 1)
        number = (
            (milliseconds << 80)
            | (7 << 76)
            | ((random_bits >> 62) << 64)
            | (2 << 62)
            | (random_bits & ((1 << 62) - 1))
        )
        return str(uuid.UUID(int=number))
    if version == "v4":
        return str(uuid.uuid4())
    raise ValueError(f"unsupported UUID version without platform extensions: {version}")


@implementation("Analyse UUID", category="Date / Time")
def analyse_uuid(value: Data, args: Args) -> str:
    identifier = uuid.UUID(to_text(value).strip())
    output = f"UUID: {identifier}\nVersion: {identifier.version}\nVariant: {identifier.variant}"
    if bool(arg(args, 0, True)) and identifier.version == 1:
        timestamp = (identifier.time - _FILETIME_EPOCH) / 10_000_000
        instant = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        output += f"\nTimestamp: {instant.isoformat()}\nNode: {identifier.node:012x}"
    return output


@implementation("Parse ObjectID timestamp", category="Date / Time")
def parse_objectid_timestamp(value: Data, _args: Args) -> str:
    text = to_text(value).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{24}", text):
        raise ValueError("ObjectID must contain 24 hexadecimal characters")
    instant = datetime.fromtimestamp(int(text[:8], 16), tz=timezone.utc)
    return instant.strftime("%a %d %B %Y %H:%M:%S UTC")
