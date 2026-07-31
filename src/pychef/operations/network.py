"""IP address, URL, URI, and indicator extraction operations."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlparse

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg, char_rep, require_int

_IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![0-9A-Fa-f:])"
)
_EMAIL = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\w.-])"
)
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\[\]{}]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:xn--)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.(?:xn--)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
)
_MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")


def _finish(matches: list[str], display_total: bool, sort: bool, unique: bool) -> str:
    if unique:
        matches = list(dict.fromkeys(matches))
    if sort:
        matches.sort()
    output = "\n".join(matches)
    return f"Total found: {len(matches)}\n\n{output}" if display_total else output


@operation("Defang IP Addresses", category="Networking")
def defang_ip(value: Data, _args: Args) -> str:
    text = to_text(value)
    text = _IPV4_CANDIDATE.sub(lambda match: match.group(0).replace(".", "[.]"), text)
    return _IPV6_CANDIDATE.sub(
        lambda match: (
            match.group(0).replace(":", "[:]") if ":" in match.group(0) else match.group(0)
        ),
        text,
    )


@operation("Defang URL", category="Networking")
def defang_url(value: Data, args: Args) -> str:
    dots = bool(arg(args, 0, True))
    http = bool(arg(args, 1, True))
    separator = bool(arg(args, 2, True))
    text = to_text(value)
    if http:
        text = re.sub(
            r"(?i)\bhttp",
            lambda match: "hxxp" + ("s" if match.group(0).lower() == "https" else ""),
            text,
        )
    if separator:
        text = text.replace("://", "[://]")
    if dots:
        text = text.replace(".", "[.]")
    return text


@operation("Fang URL", category="Networking")
def fang_url(value: Data, args: Args) -> str:
    text = to_text(value)
    if bool(arg(args, 0, True)):
        text = text.replace("[.]", ".")
    if bool(arg(args, 1, True)):
        text = re.sub(r"(?i)\bhxxp", "http", text)
    if bool(arg(args, 2, True)):
        text = text.replace("[://]", "://").replace("[:]//", "://")
    return text


@operation("Extract IP addresses", category="Networking")
def extract_ip_addresses(value: Data, args: Args) -> str:
    text = to_text(value)
    matches: list[str] = []
    if bool(arg(args, 0, True)):
        for match in _IPV4_CANDIDATE.finditer(text):
            try:
                address = ipaddress.ip_interface(match.group(0)).ip
            except ValueError:
                continue
            if bool(arg(args, 2, False)) and (
                address.is_private or address.is_loopback or address.is_link_local
            ):
                continue
            matches.append(match.group(0))
    if bool(arg(args, 1, False)):
        for match in _IPV6_CANDIDATE.finditer(text):
            try:
                ipaddress.ip_interface(match.group(0))
            except ValueError:
                continue
            matches.append(match.group(0))
    return _finish(
        matches, bool(arg(args, 3, False)), bool(arg(args, 4, False)), bool(arg(args, 5, False))
    )


@operation("Extract email addresses", category="Networking")
def extract_email_addresses(value: Data, args: Args) -> str:
    return _finish(
        _EMAIL.findall(to_text(value)),
        bool(arg(args, 0, False)),
        bool(arg(args, 1, False)),
        bool(arg(args, 2, False)),
    )


@operation("Extract URLs", category="Networking")
def extract_urls(value: Data, args: Args) -> str:
    matches = [match.rstrip(".,;:!?)") for match in _URL.findall(to_text(value))]
    return _finish(
        matches, bool(arg(args, 0, False)), bool(arg(args, 1, False)), bool(arg(args, 2, False))
    )


@operation("Extract domains", category="Networking")
def extract_domains(value: Data, args: Args) -> str:
    matches = [
        match
        for match in _DOMAIN.findall(to_text(value))
        if not all(label.isdigit() for label in match.split("."))
    ]
    return _finish(
        matches, bool(arg(args, 0, False)), bool(arg(args, 1, False)), bool(arg(args, 2, False))
    )


@operation("Extract MAC addresses", category="Networking")
def extract_mac_addresses(value: Data, args: Args) -> str:
    matches = _MAC.findall(to_text(value))
    return _finish(
        matches, bool(arg(args, 0, False)), bool(arg(args, 1, False)), bool(arg(args, 2, False))
    )


@operation("Format MAC addresses", category="Networking")
def format_mac_addresses(value: Data, args: Args) -> str:
    case = str(arg(args, 0, "Both"))
    formats: list[str] = []
    raw = re.sub(r"[^0-9A-Fa-f]", "", to_text(value))
    if len(raw) != 12:
        raise ValueError("MAC address must contain exactly 12 hexadecimal digits")
    variants = [raw] if bool(arg(args, 1, True)) else []
    if bool(arg(args, 2, True)):
        variants.append("-".join(raw[index : index + 2] for index in range(0, 12, 2)))
    if bool(arg(args, 3, True)):
        variants.append(":".join(raw[index : index + 2] for index in range(0, 12, 2)))
    if bool(arg(args, 4, False)):
        variants.append(".".join(raw[index : index + 4] for index in range(0, 12, 4)))
    if bool(arg(args, 5, False)):
        eui = raw[:6] + "fffe" + raw[6:]
        variants.append(":".join(eui[index : index + 4] for index in range(0, 16, 4)))
    if case in {"Both", "Upper only"}:
        formats.extend(variant.upper() for variant in variants)
    if case in {"Both", "Lower only"}:
        formats.extend(variant.lower() for variant in variants)
    return "\n".join(dict.fromkeys(formats))


@operation("Change IP format", category="Networking")
def change_ip_format(value: Data, args: Args) -> str:
    input_format = str(arg(args, 0, "Dotted Decimal"))
    output_format = str(arg(args, 1, "Dotted Decimal"))
    text = to_text(value).strip().lower()
    if input_format == "Dotted Decimal":
        number = int(ipaddress.IPv4Address(text))
    elif input_format == "Decimal":
        number = int(text, 10)
    elif input_format == "Octal":
        number = int(text, 8)
    else:
        number = int(text.removeprefix("0x"), 16)
    if not 0 <= number <= 0xFFFFFFFF:
        raise ValueError("IPv4 number is out of range")
    if output_format == "Dotted Decimal":
        return str(ipaddress.IPv4Address(number))
    if output_format == "Decimal":
        return str(number)
    if output_format == "Octal":
        return f"{number:012o}"
    return f"{number:08x}"


@operation("Parse IPv6 address", category="Networking")
def parse_ipv6(value: Data, _args: Args) -> str:
    address = ipaddress.IPv6Address(to_text(value).strip())
    output = f"Longhand:  {address.exploded}\nShorthand: {address.compressed}\n"
    if address.is_unspecified:
        output += (
            "\nUnspecified address corresponding to 0.0.0.0/32 in IPv4."
            "\nUnspecified address range: ::/128"
        )
    elif address.is_loopback:
        output += (
            "\nLoopback address to the local host corresponding to 127.0.0.1/8 in IPv4."
            "\nLoopback addresses range: ::1/128"
        )
    elif address.ipv4_mapped:
        output += (
            "\nIPv4-mapped IPv6 address detected."
            f"\nMapped IPv4 address: {address.ipv4_mapped}"
            "\nIPv4-mapped IPv6 addresses range: ::ffff:0:0/96"
        )
    return output


@operation("Parse IP range", category="Networking")
def parse_ip_range(value: Data, args: Args) -> str:
    text = to_text(value).strip()
    include_info = bool(arg(args, 0, True))
    enumerate_addresses = bool(arg(args, 1, True))
    allow_large = bool(arg(args, 2, False))
    if "/" in text and "\n" not in text:
        network = ipaddress.ip_network(text, strict=False)
        start, end = network.network_address, network.broadcast_address
        if network.version == 4:
            mask = str(network.netmask)
            info = (
                f"Network: {start}\nCIDR: {network.prefixlen}\nMask: {mask}"
                f"\nRange: {start} - {end}"
                f"\nTotal addresses in range: {network.num_addresses}\n\n"
            )
        else:
            count = format(float(network.num_addresses), ".16g")
            info = (
                f"Network: {start.exploded}\nShorthand: {start.compressed}"
                f"\nCIDR: {network.prefixlen}\nMask: {network.netmask.exploded}"
                f"\nRange: {start.exploded} - {end.exploded}"
                f"\nTotal addresses in range: {count}\n\n"
            )
    elif " - " in text:
        left, right = (ipaddress.ip_address(part.strip()) for part in text.split(" - ", 1))
        if left.version != right.version or int(left) > int(right):
            raise ValueError("invalid IP range")
        start, end = left, right
        count = int(end) - int(start) + 1
        info = f"Range: {start} - {end}\nTotal addresses in range: {count}\n\n"
    else:
        addresses = [
            ipaddress.ip_interface(line.strip()).ip for line in text.splitlines() if line.strip()
        ]
        if not addresses:
            raise ValueError("invalid IP range")
        start, end = min(addresses), max(addresses)
        count = int(end) - int(start) + 1
        info = f"Range: {start} - {end}\nTotal addresses in range: {count}\n\n"
    total = int(end) - int(start) + 1
    if enumerate_addresses and total > 65_536 and not allow_large:
        enumeration = ""
    elif enumerate_addresses:
        enumeration = "\n".join(
            str(ipaddress.ip_address(number)) for number in range(int(start), int(end) + 1)
        )
    else:
        enumeration = ""
    return (info if include_info else "") + enumeration


@operation("Group IP addresses", category="Networking")
def group_ip_addresses(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    prefix = require_int(arg(args, 1, 24))
    only_subnets = bool(arg(args, 2, False))
    groups: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, list[str]] = {}
    for item in to_text(value).split(delimiter):
        address = ipaddress.ip_address(item.strip())
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        groups.setdefault(network, []).append(str(address))
    if only_subnets:
        return "\n".join(str(network) for network in groups)
    return "\n\n".join(
        f"{network}\n" + "\n".join(addresses) for network, addresses in groups.items()
    )


@operation("Parse URI", category="Networking")
def parse_uri(value: Data, _args: Args) -> str:
    parsed = urlparse(to_text(value))
    output = ""
    if parsed.scheme:
        output += f"Protocol:\t{parsed.scheme}:\n"
    if parsed.username:
        auth = parsed.username + ((":" + parsed.password) if parsed.password else "")
        output += f"Auth:\t\t{auth}\n"
    if parsed.hostname:
        output += f"Hostname:\t{parsed.hostname}\n"
    if parsed.port:
        output += f"Port:\t\t{parsed.port}\n"
    if parsed.path:
        output += f"Path name:\t{parsed.path}\n"
    if parsed.query:
        query = parse_qs(parsed.query, keep_blank_values=True)
        padding = max(map(len, query), default=0)
        output += "Arguments:\n"
        for key, values in query.items():
            output += f"\t{key:<{padding}} = {','.join(values)}\n"
    if parsed.fragment:
        output += f"Hash:\t\t#{parsed.fragment}\n"
    return output
