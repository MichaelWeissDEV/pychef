"""Security tests for network operations. No external network access is used."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, cast

import pytest

from pychef import (
    ExecutionPolicy,
    NetworkPolicy,
    OperationError,
    OperationPermissionError,
    bake,
    normalize_host,
)
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


def test_normalize_host_comprehensive() -> None:
    # Trailing dots, whitespace, casing
    assert normalize_host("  EXAMPLE.COM.  ") == "example.com"
    # Bracketed IPv6
    assert normalize_host("[::1]") == "::1"
    assert normalize_host("  [2001:0DB8::0001]  ") == "2001:db8::1"
    # IPv4 literal
    assert normalize_host("127.0.0.1.") == "127.0.0.1"
    # IDNA internationalized domain
    assert normalize_host("München.DE.") == "xn--mnchen-3ya.de"


def test_check_destination_comprehensive() -> None:
    # Scheme check
    policy = NetworkPolicy(allowed_schemes=("https",))
    allowed, reason = policy.check_destination("example.com", scheme="http")
    assert allowed is False
    assert "Scheme 'http' is not permitted" in reason

    # Port checks
    port_policy = NetworkPolicy.public_only(allowed_ports=(443,), denied_ports=(8080,))
    assert port_policy.check_destination("example.com", port=443)[0] is True
    assert port_policy.check_destination("example.com", port=80)[0] is False
    assert port_policy.check_destination("example.com", port=8080)[0] is False
    assert port_policy.check_destination("example.com", port=70000)[0] is False

    # Strict deny over allow
    conflict_policy = NetworkPolicy(
        mode="public_only",
        allowed_hosts=("conflict.test", "93.184.216.34"),
        denied_hosts=("conflict.test", "93.184.216.34"),
    )
    assert conflict_policy.check_destination("conflict.test")[0] is False
    assert conflict_policy.check_destination("conflict.test", ip="93.184.216.34")[0] is False

    # Disabled mode with explicit allow
    disabled = NetworkPolicy(mode="disabled", allowed_hosts=("safe.test",))
    assert disabled.check_destination("safe.test")[0] is True
    assert disabled.check_destination("other.test")[0] is False


def test_http_request_with_trailing_dot_hostname(net: Net) -> None:
    net.answers["example.test"] = [[PUBLIC_IP]]
    # Normalization strips trailing dot so lookup succeeds
    assert (
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://example.test.:80/"]}],
            policy=ExecutionPolicy.permissive(),
        )
        == "hello"
    )
    assert net.resolutions == ["example.test"]


@pytest.fixture
def two_servers() -> Iterator[tuple[int, int, dict[str, Any]]]:
    recorded_headers_b: list[dict[str, str]] = []
    recorded_headers_a: list[dict[str, str]] = []

    class ServerAHandler(BaseHTTPRequestHandler):
        port_b: int = 0

        def do_GET(self) -> None:
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            recorded_headers_a.append(hdrs)
            if self.path == "/redirect-to-b":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.port_b}/target")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/redirect-same-origin":
                port = cast("tuple[Any, int]", self.server.server_address)[1]
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port}/same-target")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/redirect-chain":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.port_b}/redirect-back-to-a")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/redirect-loop-a":
                port = cast("tuple[Any, int]", self.server.server_address)[1]
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port}/redirect-loop-b")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/redirect-loop-b":
                port = cast("tuple[Any, int]", self.server.server_address)[1]
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port}/redirect-loop-a")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"hello")

        def log_message(self, format: str, *args: Any) -> None:
            pass

    class ServerBHandler(BaseHTTPRequestHandler):
        port_a: int = 0

        def do_GET(self) -> None:
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            recorded_headers_b.append(hdrs)
            if self.path == "/redirect-back-to-a":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.port_a}/final-target")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"server b")

        def log_message(self, format: str, *args: Any) -> None:
            pass

    httpd_a = HTTPServer(("127.0.0.1", 0), ServerAHandler)
    httpd_b = HTTPServer(("127.0.0.1", 0), ServerBHandler)
    port_a = httpd_a.server_address[1]
    port_b = httpd_b.server_address[1]
    ServerAHandler.port_b = port_b
    ServerBHandler.port_a = port_a

    thread_a = threading.Thread(target=httpd_a.serve_forever, daemon=True)
    thread_b = threading.Thread(target=httpd_b.serve_forever, daemon=True)
    thread_a.start()
    thread_b.start()

    info = {
        "headers_a": recorded_headers_a,
        "headers_b": recorded_headers_b,
    }
    yield port_a, port_b, info

    httpd_a.shutdown()
    httpd_b.shutdown()
    httpd_a.server_close()
    httpd_b.server_close()


def test_redirect_same_origin_preserves_authorization(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, info = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted())
    headers = "Authorization: Bearer TEST_TOKEN_123"
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-same-origin", headers],
            }
        ],
        policy=policy,
    )
    assert result == "hello"
    assert len(info["headers_a"]) >= 2
    target_headers = info["headers_a"][-1]
    assert target_headers.get("authorization") == "Bearer TEST_TOKEN_123"


def test_redirect_cross_origin_strips_authorization(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, info = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted())
    headers = "Authorization: Bearer SECRET_TOKEN_123"
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-to-b", headers],
            }
        ],
        policy=policy,
    )
    assert result == "server b"
    assert len(info["headers_b"]) >= 1
    target_headers = info["headers_b"][-1]
    assert "authorization" not in target_headers


def test_redirect_cross_origin_strips_cookie(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, info = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted())
    headers = "Cookie: session=SECRET_COOKIE_123\nCookie2: secret=abc"
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-to-b", headers],
            }
        ],
        policy=policy,
    )
    assert result == "server b"
    assert len(info["headers_b"]) >= 1
    target_headers = info["headers_b"][-1]
    assert "cookie" not in target_headers
    assert "cookie2" not in target_headers


def test_redirect_cross_origin_strips_proxy_authorization(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, info = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted())
    headers = "Proxy-Authorization: Basic c2VjcmV0OnBhc3M="
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-to-b", headers],
            }
        ],
        policy=policy,
    )
    assert result == "server b"
    assert len(info["headers_b"]) >= 1
    target_headers = info["headers_b"][-1]
    assert "proxy-authorization" not in target_headers


def test_redirect_cross_origin_strips_configured_sensitive_header(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, info = two_servers
    policy = ExecutionPolicy.safe(
        network=NetworkPolicy.unrestricted(
            sensitive_headers=("authorization", "cookie", "x-api-key")
        )
    )
    headers = "X-API-Key: SECRET_API_KEY_123"
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-to-b", headers],
            }
        ],
        policy=policy,
    )
    assert result == "server b"
    assert len(info["headers_b"]) >= 1
    target_headers = info["headers_b"][-1]
    assert "x-api-key" not in target_headers


def test_redirect_different_port_is_cross_origin() -> None:
    from pychef.operations.network import _get_origin

    assert _get_origin("http://127.0.0.1:8080") != _get_origin("http://127.0.0.1:8081")


def test_redirect_different_scheme_is_cross_origin() -> None:
    from pychef.operations.network import _get_origin

    assert _get_origin("http://example.com") != _get_origin("https://example.com")


def test_redirect_same_host_explicit_default_port() -> None:
    from pychef.operations.network import _get_origin

    assert _get_origin("http://example.com:80") == _get_origin("http://example.com")
    assert _get_origin("https://example.com:443") == _get_origin("https://example.com")


def test_redirect_idna_origin_normalization() -> None:
    from pychef.operations.network import _get_origin

    assert _get_origin("http://München.de") == _get_origin("http://xn--mnchen-3ya.de")
    assert _get_origin("http://EXAMPLE.COM.") == _get_origin("http://example.com")


def test_redirect_credentials_do_not_reappear(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, info = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted())
    headers = "Authorization: Bearer SECRET_CHAIN_123"
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-chain", headers],
            }
        ],
        policy=policy,
    )
    assert result == "hello"
    # Headers on server B must not have authorization
    assert "authorization" not in info["headers_b"][-1]
    # Headers on return to server A must NOT have restored authorization
    assert "authorization" not in info["headers_a"][-1]


def test_redirect_to_denied_host_never_connects(no_connect: Net) -> None:
    import urllib.request

    from pychef.operations.network import _SafeRedirectHandler

    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted(denied_hosts=("denied.test",)))
    handler = _SafeRedirectHandler(policy.network)
    req = urllib.request.Request("http://allowed.test/start")
    with pytest.raises(OperationPermissionError) as exc_info:
        cast(Any, handler).redirect_request(
            req, None, 302, "Found", {}, "http://denied.test/target"
        )
    assert "denied" in str(exc_info.value).lower()
    assert no_connect.connections == []


def test_redirect_to_denied_subnet_never_connects(net: Net) -> None:
    net.answers["allowed.test"] = [[PUBLIC_IP]]
    net.answers["sub-denied.test"] = [["10.5.5.5"]]
    policy = ExecutionPolicy.safe(
        network=NetworkPolicy.unrestricted(denied_subnets=("10.0.0.0/8",))
    )
    from pychef.operations.network import _resolve_with_policy

    with pytest.raises(OperationPermissionError) as exc_info:
        _resolve_with_policy("sub-denied.test", 80, policy.network)
    assert "denied subnet" in str(exc_info.value).lower()


def test_redirect_chain_revalidates_every_target(no_connect: Net) -> None:
    import urllib.request

    from pychef.operations.network import _SafeRedirectHandler

    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted(denied_hosts=("evil.test",)))
    handler = _SafeRedirectHandler(policy.network)
    req = urllib.request.Request("http://hop1.test/path")
    # hop 1 to hop 2 is allowed
    new_req = cast(Any, handler).redirect_request(
        req, None, 302, "Found", {}, "http://hop2.test/path"
    )
    assert new_req is not None
    # hop 2 to evil.test is denied
    with pytest.raises(OperationPermissionError):
        cast(Any, handler).redirect_request(
            new_req, None, 302, "Found", {}, "http://evil.test/path"
        )


def test_disabled_mode_allowed_subnet_resolves_hostname(net: Net) -> None:
    net.answers["internal.test"] = [["10.10.1.20"]]
    policy = ExecutionPolicy.safe(
        network=NetworkPolicy(mode="disabled", allowed_subnets=("10.10.0.0/16",))
    )
    result = bake(
        "",
        [{"op": "HTTP request", "args": ["GET", "http://internal.test/"]}],
        policy=policy,
    )
    assert result == "hello"
    assert "internal.test" in net.resolutions


def test_disabled_mode_nonmatching_subnet_blocks(net: Net) -> None:
    net.answers["other.test"] = [["192.168.1.1"]]
    policy = ExecutionPolicy.safe(
        network=NetworkPolicy(mode="disabled", allowed_subnets=("10.10.0.0/16",))
    )
    with pytest.raises(OperationError) as exc_info:
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://other.test/"]}],
            policy=policy,
        )
    err = str(exc_info.value).lower()
    assert "not permitted" in err or "disabled" in err


def test_disabled_mode_without_exceptions_skips_dns(no_connect: Net) -> None:
    policy = ExecutionPolicy.safe(network=NetworkPolicy.disabled())
    with pytest.raises(OperationError):
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://no-dns.test/"]}],
            policy=policy,
        )
    assert no_connect.resolutions == []


def test_allowed_host_denied_ip_blocks(net: Net) -> None:
    net.answers["service.example"] = [["10.1.2.3"]]
    policy = ExecutionPolicy.safe(
        network=NetworkPolicy(
            mode="public_only",
            allowed_hosts=("service.example",),
            denied_subnets=("10.0.0.0/8",),
        )
    )
    with pytest.raises(OperationError) as exc_info:
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://service.example/"]}],
            policy=policy,
        )
    assert "denied subnet" in str(exc_info.value).lower()


def test_allowed_subnet_denied_subnet_blocks() -> None:
    policy = NetworkPolicy(
        mode="unrestricted",
        allowed_subnets=("10.0.0.0/8",),
        denied_subnets=("10.1.0.0/16",),
    )
    # Deny wins over allow
    allowed, reason = policy.check_destination("host.test", ip="10.1.2.3")
    assert allowed is False
    assert "denied subnet" in reason.lower()


def test_dns_mixed_allowed_denied_answers(net: Net) -> None:
    net.answers["mixed.test"] = [[PUBLIC_IP, "10.0.0.1"]]
    policy = ExecutionPolicy.safe(network=NetworkPolicy.public_only())
    with pytest.raises(OperationError):
        bake(
            "",
            [{"op": "HTTP request", "args": ["GET", "http://mixed.test/"]}],
            policy=policy,
        )


def test_dns_rebinding_still_pinned(net: Net) -> None:
    net.answers["rebind.test"] = [[PUBLIC_IP], ["10.0.0.1"]]
    policy = ExecutionPolicy.safe(network=NetworkPolicy.public_only())
    result = bake(
        "",
        [{"op": "HTTP request", "args": ["GET", "http://rebind.test/"]}],
        policy=policy,
    )
    assert result == "hello"
    assert net.connections[0][0] == PUBLIC_IP


def test_ipv4_mapped_ipv6_private_denied() -> None:
    policy = NetworkPolicy.public_only()
    assert policy.check_destination("[::ffff:127.0.0.1]")[0] is False
    assert policy.check_destination("[::ffff:10.0.0.1]")[0] is False
    policy_unrestricted = NetworkPolicy.unrestricted(denied_subnets=("127.0.0.0/8",))
    assert policy_unrestricted.check_destination("[::ffff:127.0.0.1]")[0] is False


def test_ipv6_loopback_explicitly_allowed() -> None:
    policy = NetworkPolicy.disabled(allowed_hosts=("::1",))
    assert policy.check_destination("[::1]")[0] is True


def test_host_normalization_used_in_real_request_path(net: Net) -> None:
    net.answers["xn--mnchen-3ya.de"] = [[PUBLIC_IP]]
    result = bake(
        "",
        [{"op": "HTTP request", "args": ["GET", "http://München.de/"]}],
        policy=ExecutionPolicy.permissive(),
    )
    assert result == "hello"
    assert "xn--mnchen-3ya.de" in net.resolutions


def test_unrestricted_max_redirects_none(two_servers: tuple[int, int, dict[str, Any]]) -> None:
    port_a, _, _ = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted(max_redirects=None))
    result = bake(
        "",
        [
            {
                "op": "HTTP request",
                "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-same-origin"],
            }
        ],
        policy=policy,
    )
    assert result == "hello"


def test_max_redirects_zero_blocks(two_servers: tuple[int, int, dict[str, Any]]) -> None:
    port_a, _, _ = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted(max_redirects=0))
    with pytest.raises(OperationError):
        bake(
            "",
            [
                {
                    "op": "HTTP request",
                    "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-same-origin"],
                }
            ],
            policy=policy,
        )


def test_max_redirects_numeric_enforces_limit(
    two_servers: tuple[int, int, dict[str, Any]],
) -> None:
    port_a, _, _ = two_servers
    policy = ExecutionPolicy.safe(network=NetworkPolicy.unrestricted(max_redirects=1))
    with pytest.raises(OperationError) as exc_info:
        bake(
            "",
            [
                {
                    "op": "HTTP request",
                    "args": ["GET", f"http://127.0.0.1:{port_a}/redirect-loop-a"],
                }
            ],
            policy=policy,
        )
    assert "redirect limit reached" in str(exc_info.value).lower()
