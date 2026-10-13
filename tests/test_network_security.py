"""Security tests for network operations. No external network access is used."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from pychef import ExecutionPolicy, NetworkPolicy, OperationError, OperationPermissionError, bake
from pychef.execution import active_policy
from pychef.operations import network

PUBLIC_IP = "93.184.216.34"
_REAL_GETADDRINFO = socket.getaddrinfo
_REAL_CREATE_CONNECTION = socket.create_connection


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect-private":
            self.send_response(302)
            self.send_header("Location", "http://internal.test/secret")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"x" * 100 if self.path == "/big" else b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def server() -> Iterator[int]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


class Net:
    """Fake DNS and recorded connection attempts that land on the local test server."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, port: int | None) -> None:
        self.answers: dict[str, list[list[str]]] = {}
        self.resolutions: list[str] = []
        self.connections: list[tuple[str, int]] = []
        self.port = port

        def getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any) -> Any:
            if host in self.answers:
                self.resolutions.append(host)
                queue = self.answers[host]
                addresses = queue.pop(0) if len(queue) > 1 else queue[0]
                return [
                    (
                        socket.AF_INET6 if ":" in item else socket.AF_INET,
                        socket.SOCK_STREAM,
                        6,
                        "",
                        (item, port),
                    )
                    for item in addresses
                ]
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)

        def create_connection(address: tuple[str, int], timeout: Any = None, *a: Any) -> Any:
            self.connections.append(address)
            assert self.port is not None, f"unexpected connection to {address}"
            return _REAL_CREATE_CONNECTION(("127.0.0.1", self.port), timeout)

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "create_connection", create_connection)


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch, server: int) -> Net:
    return Net(monkeypatch, server)


@pytest.fixture
def no_connect(monkeypatch: pytest.MonkeyPatch) -> Net:
    return Net(monkeypatch, None)


def get(url: str) -> bytes:
    return network._request(url, "GET", {}, None)[3]


def test_allowed_public_connection_is_pinned_to_validated_address(net: Net) -> None:
    net.answers["example.test"] = [[PUBLIC_IP]]
    assert get("http://example.test:8080/") == b"hello"
    assert net.connections == [(PUBLIC_IP, 8080)]
    assert net.resolutions == ["example.test"]  # resolved exactly once


def test_dns_rebinding_cannot_change_the_connected_address(net: Net) -> None:
    # A rebinding resolver answers public first, loopback afterwards. Because the
    # connection reuses the single validated resolution, the second answer is never
    # consulted and no connection to loopback is made.
    net.answers["rebind.test"] = [[PUBLIC_IP], ["127.0.0.1"]]
    assert get("http://rebind.test/") == b"hello"
    assert net.resolutions == ["rebind.test"]
    assert net.connections == [(PUBLIC_IP, 80)]


def test_rebinding_answer_on_first_lookup_is_blocked(no_connect: Net) -> None:
    no_connect.answers["rebind.test"] = [["127.0.0.1"], [PUBLIC_IP]]
    with pytest.raises(ValueError, match="blocked"):
        get("http://rebind.test/")
    assert no_connect.connections == []


def test_mixed_dns_answer_is_rejected(no_connect: Net) -> None:
    no_connect.answers["mixed.test"] = [[PUBLIC_IP, "10.0.0.5"]]
    with pytest.raises(ValueError, match="blocked"):
        get("http://mixed.test/")
    assert no_connect.connections == []


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::1",
    ],
)
def test_non_public_addresses_blocked(no_connect: Net, address: str) -> None:
    no_connect.answers["t.test"] = [[address]]
    with pytest.raises(ValueError, match="blocked"):
        get("http://t.test/")
    assert no_connect.connections == []


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",  # decimal
        "http://0x7f.1/",  # hex / shortened
        "http://localhost/",
    ],
)
def test_alternative_ip_notations_blocked(no_connect: Net, url: str) -> None:
    with pytest.raises(ValueError):
        get(url)
    assert no_connect.connections == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.test/",
        "file:///etc/passwd",
        "http:///path",
        "http://user:pw@example.test/",
        "http://user@example.test/",
        "http://example.test:0/",
        "http://example.test:99999/",
        "http://example.test:abc/",
    ],
)
def test_url_syntax_rejected_without_resolution(no_connect: Net, url: str) -> None:
    no_connect.answers["example.test"] = [[PUBLIC_IP]]
    with pytest.raises(ValueError):
        get(url)
    assert no_connect.connections == []
    assert no_connect.resolutions == []


def test_redirect_to_private_host_is_blocked(net: Net) -> None:
    net.answers["example.test"] = [[PUBLIC_IP]]
    net.answers["internal.test"] = [["10.0.0.9"]]
    with pytest.raises(ValueError, match="blocked"):
        get("http://example.test/redirect-private")
    assert net.connections == [(PUBLIC_IP, 80)]  # only the first hop


def test_proxy_environment_is_ignored(net: Net, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    net.answers["example.test"] = [[PUBLIC_IP]]
    assert get("http://example.test/") == b"hello"
    assert net.connections == [(PUBLIC_IP, 80)]


def test_response_limit(net: Net, monkeypatch: pytest.MonkeyPatch) -> None:
    net.answers["example.test"] = [[PUBLIC_IP]]
    monkeypatch.setattr(network, "_MAX_HTTP_RESPONSE", 10)
    with pytest.raises(ValueError, match="safety limit"):
        get("http://example.test/big")


def test_unresolvable_host(no_connect: Net, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(*_a: Any, **_k: Any) -> Any:
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", failing)
    with pytest.raises(ValueError, match="resolve"):
        get("http://missing.test/")


def test_header_injection_rejected() -> None:
    with pytest.raises(OperationError, match="Unsafe managed HTTP header"):
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://x.test/", "Host: evil"]}],
            policy=ExecutionPolicy.permissive(),
        )


# --- permissions -----------------------------------------------------------


def test_restrictive_policy_blocks_network_without_dns_or_connection(no_connect: Net) -> None:
    no_connect.answers["example.test"] = [[PUBLIC_IP]]
    for recipe in (
        [{"op": "HTTP request", "args": ["GET", "http://example.test/"]}],
        [{"op": "DNS over HTTPS", "args": ["http://example.test/resolve"]}],
        [
            {"op": "Fork", "args": ["\n", "\n"]},
            {"op": "HTTP request", "args": ["GET", "http://example.test/"]},
        ],
    ):
        with pytest.raises(OperationPermissionError) as info:
            bake("a.test", recipe, policy=ExecutionPolicy())
        assert info.value.error_code == "permission_denied"
    assert no_connect.resolutions == []
    assert no_connect.connections == []


def test_network_blocked_even_when_operation_is_called_directly(no_connect: Net) -> None:
    no_connect.answers["example.test"] = [[PUBLIC_IP]]
    with active_policy(ExecutionPolicy()), pytest.raises(OperationPermissionError):
        get("http://example.test/")
    assert no_connect.resolutions == []


def test_permission_error_not_swallowed_by_fork_ignore_errors(no_connect: Net) -> None:
    recipe = [
        {"op": "Fork", "args": ["\n", "\n", True]},
        {"op": "HTTP request", "args": ["GET", "http://example.test/"]},
    ]
    with pytest.raises(OperationPermissionError):
        bake("a", recipe, policy=ExecutionPolicy())


def test_allow_network_policy_permits_request(net: Net) -> None:
    net.answers["example.test"] = [[PUBLIC_IP]]
    recipe = [{"op": "HTTP request", "args": ["GET", "http://example.test/"]}]
    assert bake("", recipe, policy=ExecutionPolicy(allow_network=True)) == "hello"


def test_default_without_policy_blocks_network(no_connect: Net) -> None:
    no_connect.answers["example.test"] = [[PUBLIC_IP]]
    with pytest.raises(OperationPermissionError):
        bake("", [{"op": "HTTP request", "args": ["GET", "http://example.test/"]}])


def test_permissive_policy_permits_network(net: Net) -> None:
    net.answers["example.test"] = [[PUBLIC_IP]]
    assert (
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://example.test/"]}],
            policy=ExecutionPolicy.permissive(),
        )
        == "hello"
    )


def test_network_policy_hostname_normalization() -> None:
    pol = NetworkPolicy(
        mode="public_only",
        allowed_hosts=("Example.Com.", "MÜNCHEN.DE"),
        denied_hosts=("EVIL.COM.",),
    )
    # Check normalized tuples
    assert "example.com" in pol.allowed_hosts
    assert "xn--mnchen-3ya.de" in pol.allowed_hosts
    assert "evil.com" in pol.denied_hosts

    # Check matches with trailing dots and casing
    assert pol.is_host_allowed("EXAMPLE.COM.") is True
    assert pol.is_host_allowed("example.com") is True
    assert pol.is_host_allowed("münchen.de") is True
    assert pol.is_host_allowed("xn--mnchen-3ya.de") is True

    # Blocked host matches
    assert pol.is_host_allowed("EVIL.COM.") is False
    assert pol.is_host_allowed("evil.com") is False


def test_network_policy_deny_overrides_allow() -> None:
    # When a host is in both allowed and denied, denied wins
    pol = NetworkPolicy(
        mode="public_only",
        allowed_hosts=("conflict.test",),
        denied_hosts=("conflict.test",),
    )
    assert pol.is_host_allowed("conflict.test") is False

    # When an IP is in both allowed and denied subnets, denied subnet wins
    pol_subnet = NetworkPolicy(
        mode="public_only",
        allowed_subnets=("93.184.216.0/24",),
        denied_subnets=("93.184.216.34/32",),
    )
    import ipaddress

    ip = ipaddress.ip_address(PUBLIC_IP)
    assert pol_subnet.is_ip_allowed(ip) is False


def test_network_policy_unrestricted_allows_private_and_loopback(net: Net) -> None:
    pol = NetworkPolicy.unrestricted()
    import ipaddress

    loopback = ipaddress.ip_address("127.0.0.1")
    private = ipaddress.ip_address("10.0.0.1")
    public = ipaddress.ip_address(PUBLIC_IP)
    assert pol.is_ip_allowed(loopback) is True
    assert pol.is_ip_allowed(private) is True
    assert pol.is_ip_allowed(public) is True


def test_network_policy_factories_and_attributes() -> None:
    disabled = NetworkPolicy.disabled()
    assert disabled.mode == "disabled"
    assert disabled.is_host_allowed("example.com") is False

    public = NetworkPolicy.public_only(timeout_seconds=15.0, max_redirects=3)
    assert public.mode == "public_only"
    assert public.timeout_seconds == 15.0
    assert public.max_redirects == 3

    unrestricted = NetworkPolicy.unrestricted(timeout_seconds=None, max_redirects=None)
    assert unrestricted.mode == "unrestricted"
    assert unrestricted.timeout_seconds is None
    assert unrestricted.max_redirects is None
