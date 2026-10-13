"""IP address, URL, URI, and indicator extraction operations."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from http.client import HTTPMessage
from typing import IO, Any, cast
from urllib.parse import parse_qs, urlencode, urlparse

from ..errors import OperationPermissionError
from ..execution import current_policy
from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg, char_rep, require_int

_HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE", "OPTIONS"}
_MAX_HTTP_RESPONSE = 64 * 1024 * 1024
_HTTP_TIMEOUT = 30.0

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


@implementation("Defang IP Addresses", category="Networking")
def defang_ip(value: Data, _args: Args) -> str:
    text = to_text(value)
    text = _IPV4_CANDIDATE.sub(lambda match: match.group(0).replace(".", "[.]"), text)
    return _IPV6_CANDIDATE.sub(
        lambda match: (
            match.group(0).replace(":", "[:]") if ":" in match.group(0) else match.group(0)
        ),
        text,
    )


@implementation("Defang URL", category="Networking")
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


@implementation("Fang URL", category="Networking")
def fang_url(value: Data, args: Args) -> str:
    text = to_text(value)
    if bool(arg(args, 0, True)):
        text = text.replace("[.]", ".")
    if bool(arg(args, 1, True)):
        text = re.sub(r"(?i)\bhxxp", "http", text)
    if bool(arg(args, 2, True)):
        text = text.replace("[://]", "://").replace("[:]//", "://")
    return text


@implementation("Extract IP addresses", category="Networking")
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


@implementation("Extract email addresses", category="Networking")
def extract_email_addresses(value: Data, args: Args) -> str:
    return _finish(
        _EMAIL.findall(to_text(value)),
        bool(arg(args, 0, False)),
        bool(arg(args, 1, False)),
        bool(arg(args, 2, False)),
    )


@implementation("Extract URLs", category="Networking")
def extract_urls(value: Data, args: Args) -> str:
    matches = [match.rstrip(".,;:!?)") for match in _URL.findall(to_text(value))]
    return _finish(
        matches, bool(arg(args, 0, False)), bool(arg(args, 1, False)), bool(arg(args, 2, False))
    )


@implementation("Extract domains", category="Networking")
def extract_domains(value: Data, args: Args) -> str:
    matches = [
        match
        for match in _DOMAIN.findall(to_text(value))
        if not all(label.isdigit() for label in match.split("."))
    ]
    return _finish(
        matches, bool(arg(args, 0, False)), bool(arg(args, 1, False)), bool(arg(args, 2, False))
    )


@implementation("Extract MAC addresses", category="Networking")
def extract_mac_addresses(value: Data, args: Args) -> str:
    matches = _MAC.findall(to_text(value))
    return _finish(
        matches, bool(arg(args, 0, False)), bool(arg(args, 1, False)), bool(arg(args, 2, False))
    )


@implementation("Format MAC addresses", category="Networking")
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


@implementation("Change IP format", category="Networking")
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


@implementation("Parse IPv6 address", category="Networking")
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


@implementation("Parse IP range", category="Networking")
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


@implementation("Group IP addresses", category="Networking")
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


@implementation("Parse URI", category="Networking")
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


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether *address* is a globally routable unicast address.

    IPv4-mapped (``::ffff:a.b.c.d``), IPv4-compatible-looking, 6to4 and NAT64
    wrappers are unwrapped so that they cannot smuggle a private IPv4 target.
    """
    if isinstance(address, ipaddress.IPv6Address):
        embedded: list[ipaddress.IPv4Address] = []
        if address.ipv4_mapped is not None:
            embedded.append(address.ipv4_mapped)
        if address.sixtofour is not None:
            embedded.append(address.sixtofour)
        if address in ipaddress.ip_network("64:ff9b::/96"):
            embedded.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
        if address.teredo is not None:
            embedded.extend(address.teredo)
        if any(not _is_public(item) for item in embedded):
            return False
    return address.is_global and not address.is_multicast


def _parse_http_url(value: str) -> tuple[str, str, int]:
    """Validate the syntax of *value* and return ``(scheme, hostname, port)``."""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use HTTP or HTTPS and contain a hostname")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("Credentials embedded in URLs are not permitted")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise ValueError("URL contains an invalid port")
    return parsed.scheme, parsed.hostname, port


def _resolve_public(host: str, port: int) -> list[str]:
    """Resolve *host* once and return only verified public addresses.

    Raises ``ValueError`` if resolution fails, yields nothing, or *any* returned
    address is non-global (a mixed answer is rejected as suspicious).
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"Could not resolve HTTP host: {host}") from exc
    addresses: list[str] = []
    for info in infos:
        text = str(info[4][0]).split("%", 1)[0]
        if not _is_public(ipaddress.ip_address(text)):
            raise ValueError(
                "Requests to local, private, reserved, or non-global addresses are blocked"
            )
        if text not in addresses:
            addresses.append(text)
    if not addresses:
        raise ValueError(f"Could not resolve HTTP host: {host}")
    return addresses


def _safe_public_url(value: str) -> str:
    """Pre-flight validation of *value* (syntax and current DNS answer).

    This check alone is subject to DNS rebinding.  The actual connection is made
    by :class:`_PinnedConnectionMixin`, which re-validates the addresses it
    really connects to.
    """
    _, host, port = _parse_http_url(value)
    _resolve_public(host, port)
    return value


def _connect_pinned(host: str, port: int, timeout: float | None) -> socket.socket:
    """Connect to a validated address; resolution and validation happen right here."""
    last_error: OSError | None = None
    for address in _resolve_public(host, port):
        try:
            return socket.create_connection((address, port), timeout)
        except OSError as exc:
            last_error = exc
    raise ConnectionError(f"Could not connect to {host}:{port}") from last_error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that only ever connects to the addresses it validated."""

    def connect(self) -> None:
        self.sock = _connect_pinned(self.host, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with pinned addresses; TLS still verifies the hostname."""

    def connect(self) -> None:
        sock = _connect_pinned(self.host, self.port, self.timeout)
        context = cast(ssl.SSLContext, getattr(self, "_context"))  # noqa: B009
        self.sock = context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self) -> None:
        super().__init__(context=ssl.create_default_context())

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            _PinnedHTTPSConnection,
            req,
            context=getattr(self, "_context"),  # noqa: B009
        )


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        _parse_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _require_network_permission() -> None:
    policy = current_policy()
    if policy is not None and not policy.allow_network:
        raise OperationPermissionError(
            "HTTP request", "network access is not permitted by the execution policy"
        )


def _request(
    url: str, method: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, str, HTTPMessage, bytes]:
    _require_network_permission()
    _parse_http_url(url)
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    # An empty ProxyHandler ignores HTTP(S)_PROXY: a proxy would resolve and
    # connect on our behalf and bypass the address check.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _PinnedHTTPHandler(),
        _PinnedHTTPSHandler(),
        _SafeRedirectHandler(),
    )
    try:
        response: Any = opener.open(request, timeout=_HTTP_TIMEOUT)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        data = response.read(_MAX_HTTP_RESPONSE + 1)
        if len(data) > _MAX_HTTP_RESPONSE:
            raise ValueError("HTTP response exceeded the 64 MiB safety limit")
        status = response.status if response.status is not None else response.getcode()
        if status is None:
            raise ValueError("HTTP response did not contain a status code")
        return (
            cast(int, status),
            str(response.reason),
            cast(HTTPMessage, response.headers),
            cast(bytes, data),
        )


@implementation("HTTP request", category="Networking")
def http_request(value: Data, args: Args) -> Data:
    method = str(arg(args, 0, "GET")).upper()
    url = str(arg(args, 1, ""))
    if not url:
        return ""
    if method not in _HTTP_METHODS:
        raise ValueError(f"Unsupported HTTP method: {method}")
    headers: dict[str, str] = {}
    for line in str(arg(args, 2, "")).splitlines():
        if not line.strip():
            continue
        name, separator, header_value = line.partition(":")
        if not separator or not name.strip() or "\n" in header_value or "\r" in header_value:
            raise ValueError(f"Could not parse HTTP header line: {line}")
        if name.strip().lower() in {"host", "content-length", "transfer-encoding"}:
            raise ValueError(f"Unsafe managed HTTP header: {name.strip()}")
        headers[name.strip()] = header_value.strip()
    body = None if method in {"GET", "HEAD"} else to_text(value).encode()
    status, reason, response_headers, data = _request(url, method, headers, body)
    text = data.decode("utf-8", "replace")
    if not bool(arg(args, 4, False)):
        return text
    exposed = "".join(f"    {name}: {item}\n" for name, item in response_headers.items())
    return f"####\n  Status: {status} {reason}\n  Exposed headers:\n{exposed}####\n\n{text}"


@implementation("DNS over HTTPS", category="Networking")
def dns_over_https(value: Data, args: Args) -> Data:
    resolver = str(arg(args, 0, "https://dns.google.com/resolve"))
    request_type = str(arg(args, 1, "A")).upper()
    answer_only = bool(arg(args, 2, False))
    disable_dnssec = bool(arg(args, 3, False))
    domain = to_text(value).strip().encode("idna").decode()
    if len(domain) > 253 or not re.fullmatch(
        r"(?:[A-Za-z0-9_*-]{1,63}\.)*[A-Za-z0-9_*-]{1,63}\.?", domain
    ):
        raise ValueError("Invalid DNS name")
    if not re.fullmatch(r"[A-Z0-9-]{1,16}", request_type):
        raise ValueError("Invalid DNS record type")
    separator = "&" if "?" in resolver else "?"
    url = (
        resolver
        + separator
        + urlencode({"name": domain, "type": request_type, "cd": str(disable_dnssec).lower()})
    )
    status, _, _, body = _request(url, "GET", {"Accept": "application/dns-json"}, None)
    if status < 200 or status >= 300:
        raise ValueError(f"DNS-over-HTTPS resolver returned HTTP {status}")
    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("DNS-over-HTTPS resolver returned invalid JSON") from exc
    if answer_only:
        result = [answer.get("data") for answer in result.get("Answer", [])]
    return json.dumps(result, ensure_ascii=False, indent=2)
