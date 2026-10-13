"""Execution policy, network permissions, and per-execution context.

``ExecutionPolicy`` is a frozen, validated description of the limits and
permissions that apply to one recipe execution.  ``ExecutionContext`` is
created per execution (never a global singleton) and shared by all nested
recipes (Fork, Subsection, ...), so budgets cannot be reset by recursion.

All in-process limits are **cooperative**: they are checked by the engine
between steps and after each operation.  They cannot interrupt a long-running
computation inside a single C-extension or catastrophic regex without
process-level isolation; for hard isolation see :mod:`pychef.worker`.
"""

from __future__ import annotations

import contextvars
import ipaddress
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from time import perf_counter
from typing import Any, Literal

from .errors import ExecutionLimitError, ExecutionTimeoutError, OperationPermissionError
from .types import Data, TraceStep

#: Operations that open network connections.
NETWORK_OPERATIONS = frozenset({"HTTP request", "DNS over HTTPS"})

_TRACE_ENTRY_OVERHEAD = 192  # conservative estimate of bytes per recorded trace step


def normalize_host(host: str) -> str:
    """Canonicalize a hostname or IP address literal.

    Strips surrounding whitespace and IPv6 brackets, removes trailing dots,
    canonicalizes IP literals via :mod:`ipaddress`, and applies IDNA encoding
    with lowercasing to domain names.
    """
    text = str(host).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    text = text.rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    text = text.lower()
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return text


_normalize_host = normalize_host


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether *address* is a globally routable unicast address."""
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


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Configurable network policy governing outbound HTTP and DNS-over-HTTPS requests.

    Modes:

    * ``"disabled"``: Outbound requests are blocked unless the target is explicitly
      matched by ``allowed_hosts`` or ``allowed_subnets``.
    * ``"public_only"``: Only public, globally routable addresses are allowed; private,
      loopback, link-local, and reserved ranges are blocked unless explicitly listed in
      ``allowed_hosts`` or ``allowed_subnets``. Strict SSRF and DNS rebinding protections apply.
    * ``"unrestricted"``: All destinations (including private, localhost, link-local)
      are permitted without restriction.
    """

    mode: Literal["disabled", "public_only", "unrestricted"] = "disabled"
    allowed_hosts: tuple[str, ...] = ()
    denied_hosts: tuple[str, ...] = ()
    allowed_subnets: tuple[str, ...] = ()
    denied_subnets: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] | None = None
    denied_ports: tuple[int, ...] = ()
    allowed_schemes: tuple[str, ...] = ("http", "https")
    max_response_bytes: int | None = 64 * 1024 * 1024
    timeout_seconds: float | None = 30.0
    allow_redirects: bool = True
    max_redirects: int | None = 5

    def __post_init__(self) -> None:
        if self.mode not in {"disabled", "public_only", "unrestricted"}:
            raise ValueError(
                f"mode must be 'disabled', 'public_only', or 'unrestricted', got {self.mode!r}"
            )
        # Normalize hostnames to lowercase tuples without trailing dots
        object.__setattr__(
            self,
            "allowed_hosts",
            tuple(_normalize_host(h) for h in self.allowed_hosts),
        )
        object.__setattr__(
            self,
            "denied_hosts",
            tuple(_normalize_host(h) for h in self.denied_hosts),
        )
        object.__setattr__(
            self,
            "allowed_schemes",
            tuple(str(s).lower().strip() for s in self.allowed_schemes),
        )
        # Validate subnets
        for subnet in self.allowed_subnets:
            ipaddress.ip_network(subnet, strict=False)
        for subnet in self.denied_subnets:
            ipaddress.ip_network(subnet, strict=False)
        # Validate ports
        if self.allowed_ports is not None:
            for port in self.allowed_ports:
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port {port} out of range 1..65535")
        for port in self.denied_ports:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of range 1..65535")
        # Validate limits
        if self.max_response_bytes is not None and (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or self.max_response_bytes < 0
        ):
            raise ValueError("max_response_bytes must be None or a non-negative integer")
        if self.timeout_seconds is not None and (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be None or a positive number")
        if self.max_redirects is not None and (
            isinstance(self.max_redirects, bool)
            or not isinstance(self.max_redirects, int)
            or self.max_redirects < 0
        ):
            raise ValueError("max_redirects must be None or a non-negative integer")

    @classmethod
    def disabled(cls, **kwargs: Any) -> NetworkPolicy:
        """Completely disable outbound network requests by default."""
        policy = cls(mode="disabled")
        return policy.with_overrides(**kwargs) if kwargs else policy

    @classmethod
    def public_only(cls, **kwargs: Any) -> NetworkPolicy:
        """Allow requests only to verified public IP addresses with SSRF protection."""
        policy = cls(mode="public_only")
        return policy.with_overrides(**kwargs) if kwargs else policy

    @classmethod
    def unrestricted(cls, **kwargs: Any) -> NetworkPolicy:
        """Allow outbound requests to any address, including private, local, and custom ports."""
        policy = cls(mode="unrestricted", max_response_bytes=None)
        return policy.with_overrides(**kwargs) if kwargs else policy

    def with_overrides(self, **kwargs: Any) -> NetworkPolicy:
        """Return a new immutable NetworkPolicy with the specified overrides."""
        return replace(self, **kwargs)

    def check_destination(
        self,
        host: str,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str | None = None,
        port: int | None = None,
        scheme: str | None = None,
    ) -> tuple[bool, str]:
        """Check whether a destination (host, IP, port, scheme) is permitted.

        Returns a tuple of ``(allowed, reason)``.
        Strict deny-over-allow precedence is enforced.
        """
        if scheme is not None:
            norm_scheme = str(scheme).lower().strip()
            if norm_scheme not in self.allowed_schemes:
                return False, f"Scheme '{norm_scheme}' is not permitted by network policy"

        if port is not None:
            if not (1 <= port <= 65535):
                return False, f"Port {port} out of range 1..65535"
            if port in self.denied_ports:
                return False, f"Port {port} is explicitly denied by network policy"
            if self.allowed_ports is not None and port not in self.allowed_ports:
                return False, f"Port {port} is not in allowed ports"

        norm_host = normalize_host(host)

        # Check if the host itself is explicitly denied
        if norm_host in self.denied_hosts:
            return False, f"Host '{norm_host}' is explicitly denied by network policy"

        # Determine target IP address object if provided or if host is an IP literal
        parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        if ip is not None:
            if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                parsed_ip = ip
            else:
                try:
                    parsed_ip = ipaddress.ip_address(normalize_host(str(ip)))
                except ValueError:
                    return False, f"Invalid IP address: {ip}"
        else:
            try:
                parsed_ip = ipaddress.ip_address(norm_host)
            except ValueError:
                parsed_ip = None

        if parsed_ip is not None:
            ip_text = str(parsed_ip)
            if ip_text in self.denied_hosts:
                return False, f"IP '{ip_text}' is explicitly denied by network policy"
            for denied_sub in self.denied_subnets:
                if parsed_ip in ipaddress.ip_network(denied_sub, strict=False):
                    return False, f"IP '{ip_text}' is in denied subnet '{denied_sub}'"

        # If not denied, check explicit allow rules
        host_explicitly_allowed = norm_host in self.allowed_hosts

        ip_explicitly_allowed = False
        if parsed_ip is not None:
            ip_text = str(parsed_ip)
            if ip_text in self.allowed_hosts or any(
                parsed_ip in ipaddress.ip_network(allowed_sub, strict=False)
                for allowed_sub in self.allowed_subnets
            ):
                ip_explicitly_allowed = True

        if host_explicitly_allowed or ip_explicitly_allowed:
            return True, "Destination explicitly allowed"

        # Mode fallbacks
        if self.mode == "disabled":
            return False, "network access is not permitted by the execution policy"

        if self.mode == "unrestricted":
            return True, "Permitted under unrestricted network policy"

        if self.mode == "public_only":
            if parsed_ip is not None:
                if not _is_public(parsed_ip):
                    return (
                        False,
                        "Requests to local, private, reserved, or non-global addresses are blocked",
                    )
                return True, "Permitted public address"
            return True, "Hostname permitted for public DNS resolution"

        return False, "Destination blocked"

    def is_host_allowed(self, host: str) -> bool:
        """Check if a hostname is permitted under this policy."""
        allowed, _ = self.check_destination(host=host)
        return allowed

    def is_ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> bool:
        """Check if an IP address is permitted under this policy."""
        allowed, _ = self.check_destination(host=str(ip), ip=ip)
        return allowed


@dataclass(frozen=True, slots=True, init=False)
class ExecutionPolicy:
    """Resource and permission limits for one recipe execution.

    ``None`` explicitly disables the respective numeric limit.

    Named profiles:

    * :meth:`safe` (default): Conservative resource limits, network disabled.
    * :meth:`untrusted`: Strict limits for untrusted data and recipes.
    * :meth:`unrestricted`: All numeric limits disabled, unrestricted network access.
    * :meth:`permissive`: Backward-compatible profile with unlimited numeric limits
      and public network access.
    """

    max_memory_bytes: int | None
    max_input_bytes: int | None
    max_output_bytes: int | None
    max_steps: int | None
    max_branches: int | None
    max_recursion_depth: int | None
    max_trace_bytes: int | None
    cooperative_deadline_seconds: float | None
    network: NetworkPolicy

    def __init__(
        self,
        *,
        max_memory_bytes: int | None = 512 * 1024**2,
        max_input_bytes: int | None = 16 * 1024**2,
        max_output_bytes: int | None = 64 * 1024**2,
        max_steps: int | None = 10_000,
        max_branches: int | None = 10_000,
        max_recursion_depth: int | None = 8,
        max_trace_bytes: int | None = 1024**2,
        cooperative_deadline_seconds: float | None = 30.0,
        network: NetworkPolicy | None = None,
        allow_network: bool | None = None,
    ) -> None:
        if allow_network is not None:
            if not isinstance(allow_network, bool):
                raise TypeError("allow_network must be a bool")
            if network is not None:
                has_net = (
                    network.mode != "disabled"
                    or bool(network.allowed_hosts)
                    or bool(network.allowed_subnets)
                )
                if allow_network and not has_net:
                    raise ValueError(
                        "Conflicting network configuration: allow_network=True "
                        "but network policy is disabled"
                    )
                if not allow_network and has_net:
                    raise ValueError(
                        "Conflicting network configuration: allow_network=False "
                        "but network policy permits network"
                    )
                resolved_network = network
            else:
                resolved_network = (
                    NetworkPolicy.public_only() if allow_network else NetworkPolicy.disabled()
                )
        else:
            resolved_network = network if network is not None else NetworkPolicy.disabled()

        for name, value in (
            ("max_memory_bytes", max_memory_bytes),
            ("max_input_bytes", max_input_bytes),
            ("max_output_bytes", max_output_bytes),
            ("max_steps", max_steps),
            ("max_recursion_depth", max_recursion_depth),
            ("max_branches", max_branches),
            ("max_trace_bytes", max_trace_bytes),
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be None or a non-negative integer, got {value!r}")

        if cooperative_deadline_seconds is not None and (
            isinstance(cooperative_deadline_seconds, bool)
            or not isinstance(cooperative_deadline_seconds, (int, float))
            or cooperative_deadline_seconds <= 0
        ):
            raise ValueError("cooperative_deadline_seconds must be None or a positive number")

        object.__setattr__(self, "max_memory_bytes", max_memory_bytes)
        object.__setattr__(self, "max_input_bytes", max_input_bytes)
        object.__setattr__(self, "max_output_bytes", max_output_bytes)
        object.__setattr__(self, "max_steps", max_steps)
        object.__setattr__(self, "max_branches", max_branches)
        object.__setattr__(self, "max_recursion_depth", max_recursion_depth)
        object.__setattr__(self, "max_trace_bytes", max_trace_bytes)
        object.__setattr__(self, "cooperative_deadline_seconds", cooperative_deadline_seconds)
        object.__setattr__(self, "network", resolved_network)

    @property
    def allow_network(self) -> bool:
        """Compatibility property reflecting whether network requests are permitted."""
        return (
            self.network.mode != "disabled"
            or bool(self.network.allowed_hosts)
            or bool(self.network.allowed_subnets)
        )

    @classmethod
    def safe(cls, **kwargs: Any) -> ExecutionPolicy:
        """Standard safe configuration: conservative limits, network disabled."""
        policy = cls()
        return policy.with_overrides(**kwargs) if kwargs else policy

    @classmethod
    def untrusted(cls, **kwargs: Any) -> ExecutionPolicy:
        """Conservative profile for untrusted recipes and inputs."""
        policy = cls(
            max_memory_bytes=128 * 1024 * 1024,
            max_input_bytes=16 * 1024 * 1024,
            max_output_bytes=64 * 1024 * 1024,
            max_steps=10_000,
            max_recursion_depth=8,
            max_branches=10_000,
            max_trace_bytes=1024 * 1024,
            cooperative_deadline_seconds=30.0,
            network=NetworkPolicy.disabled(),
        )
        return policy.with_overrides(**kwargs) if kwargs else policy

    @classmethod
    def unrestricted(cls, **kwargs: Any) -> ExecutionPolicy:
        """Unrestricted configuration: all limits disabled, network unrestricted."""
        policy = cls(
            max_memory_bytes=None,
            max_input_bytes=None,
            max_output_bytes=None,
            max_steps=None,
            max_recursion_depth=None,
            max_branches=None,
            max_trace_bytes=None,
            cooperative_deadline_seconds=None,
            network=NetworkPolicy.unrestricted(),
        )
        return policy.with_overrides(**kwargs) if kwargs else policy

    @classmethod
    def permissive(cls, **kwargs: Any) -> ExecutionPolicy:
        """Legacy profile: numeric limits disabled, public network allowed."""
        policy = cls(
            max_memory_bytes=None,
            max_input_bytes=None,
            max_output_bytes=None,
            max_steps=None,
            max_recursion_depth=None,
            max_branches=None,
            max_trace_bytes=None,
            cooperative_deadline_seconds=None,
            network=NetworkPolicy.public_only(),
        )
        return policy.with_overrides(**kwargs) if kwargs else policy

    legacy = permissive

    def with_overrides(self, **kwargs: Any) -> ExecutionPolicy:
        """Return a new immutable ExecutionPolicy with specified overrides."""
        if "allow_network" in kwargs:
            allow = kwargs.pop("allow_network")
            if not isinstance(allow, bool):
                raise TypeError("allow_network must be a bool")
            if "network" in kwargs:
                net = kwargs["network"]
                if net is not None:
                    has_net = (
                        net.mode != "disabled"
                        or bool(net.allowed_hosts)
                        or bool(net.allowed_subnets)
                    )
                    if allow and not has_net:
                        raise ValueError(
                            "Conflicting network configuration: allow_network=True "
                            "but network policy is disabled"
                        )
                    if not allow and has_net:
                        raise ValueError(
                            "Conflicting network configuration: allow_network=False "
                            "but network policy permits network"
                        )
            else:
                kwargs["network"] = (
                    NetworkPolicy.public_only() if allow else NetworkPolicy.disabled()
                )

        allowed_fields = {
            "max_memory_bytes",
            "max_input_bytes",
            "max_output_bytes",
            "max_steps",
            "max_branches",
            "max_recursion_depth",
            "max_trace_bytes",
            "cooperative_deadline_seconds",
            "network",
        }
        unknown = set(kwargs) - allowed_fields
        if unknown:
            raise TypeError(
                f"Unexpected keyword argument(s) for ExecutionPolicy: {sorted(unknown)}"
            )

        return ExecutionPolicy(
            max_memory_bytes=kwargs.get("max_memory_bytes", self.max_memory_bytes),
            max_input_bytes=kwargs.get("max_input_bytes", self.max_input_bytes),
            max_output_bytes=kwargs.get("max_output_bytes", self.max_output_bytes),
            max_steps=kwargs.get("max_steps", self.max_steps),
            max_branches=kwargs.get("max_branches", self.max_branches),
            max_recursion_depth=kwargs.get("max_recursion_depth", self.max_recursion_depth),
            max_trace_bytes=kwargs.get("max_trace_bytes", self.max_trace_bytes),
            cooperative_deadline_seconds=kwargs.get(
                "cooperative_deadline_seconds", self.cooperative_deadline_seconds
            ),
            network=kwargs.get("network", self.network),
        )


def data_size(value: Data | int) -> int:
    """Size in bytes; ``str`` is measured as UTF-8 so text and bytes are comparable."""
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode("utf-8", "surrogatepass"))


def _within(value: Data | int, limit: int) -> bool:
    if isinstance(value, int):
        return value <= limit
    if isinstance(value, bytes):
        return len(value) <= limit
    if len(value) > limit:  # UTF-8 needs at least one byte per character
        return False
    if len(value) * 4 <= limit:  # and at most four
        return True
    return data_size(value) <= limit


@dataclass(slots=True)
class ExecutionContext:
    """Mutable state shared by an execution and all nested executions."""

    policy: ExecutionPolicy = field(default_factory=ExecutionPolicy.safe)
    trace_enabled: bool = False
    execution_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    steps: int = 0
    branches: int = 0
    depth: int = 0
    position: int = 0
    branch_path: tuple[int, ...] = ()
    trace: list[TraceStep] = field(default_factory=list)
    _trace_bytes: int = 0
    _started: float = field(default_factory=perf_counter)
    _cancelled: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def elapsed(self) -> float:
        return perf_counter() - self._started

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Request cooperative cancellation; takes effect at the next step."""
        self._cancelled.set()

    def _limit(self, limit: str, message: str, operation: str | None, step: int | None) -> Any:
        return ExecutionLimitError(
            limit,
            message,
            operation_name=operation,
            step_index=step,
            branch_path=self.branch_path,
            execution_id=self.execution_id,
        )

    def charge_step(self, operation: str, step_index: int) -> None:
        """Count one engine step (including flow control and repeated jumps)."""
        self.position = step_index
        if self._cancelled.is_set():
            raise self._limit("cancelled", "execution was cancelled", operation, step_index)
        deadline = self.policy.cooperative_deadline_seconds
        if deadline is not None and self.elapsed > deadline:
            raise ExecutionTimeoutError(
                f"cooperative deadline of {deadline}s exceeded between steps",
                operation_name=operation,
                step_index=step_index,
                branch_path=self.branch_path,
                execution_id=self.execution_id,
            )
        with self._lock:
            self.steps += 1
            exceeded = self.policy.max_steps is not None and self.steps > self.policy.max_steps
        if exceeded:
            raise self._limit(
                "max_steps",
                f"step budget of {self.policy.max_steps} exceeded",
                operation,
                step_index,
            )

    def charge_branch(self, operation: str, step_index: int) -> None:
        with self._lock:
            self.branches += 1
            exceeded = (
                self.policy.max_branches is not None and self.branches > self.policy.max_branches
            )
        if exceeded:
            raise self._limit(
                "max_branches",
                f"branch budget of {self.policy.max_branches} exceeded",
                operation,
                step_index,
            )

    @contextmanager
    def nested(self, operation: str, step_index: int) -> Iterator[None]:
        """Enter a nested recipe; depth is restored on exit, counters are not."""
        limit = self.policy.max_recursion_depth
        if limit is not None and self.depth + 1 > limit:
            raise self._limit(
                "max_recursion_depth",
                f"recursion depth limit of {limit} exceeded",
                operation,
                step_index,
            )
        saved_path = self.branch_path
        self.depth += 1
        self.branch_path = (*saved_path, step_index)
        try:
            yield
        finally:
            self.depth -= 1
            self.branch_path = saved_path

    def check_memory(
        self, value_or_size: Data | int, operation: str | None = None, step: int | None = None
    ) -> None:
        limit = self.policy.max_memory_bytes
        if limit is None:
            return
        size = value_or_size if isinstance(value_or_size, int) else data_size(value_or_size)
        if size > limit:
            raise self._limit(
                "max_memory_bytes",
                f"memory budget of {limit} bytes exceeded ({size} bytes requested)",
                operation,
                step,
            )

    def check_input(
        self, value: Data | int, operation: str | None = None, step: int | None = None
    ) -> None:
        self.check_memory(value, operation, step)
        limit = self.policy.max_input_bytes
        if limit is not None and not _within(value, limit):
            raise self._limit("max_input_bytes", f"input exceeds {limit} bytes", operation, step)

    def check_output(
        self, value: Data | int, operation: str | None = None, step: int | None = None
    ) -> None:
        self.check_memory(value, operation, step)
        limit = self.policy.max_output_bytes
        if limit is not None and not _within(value, limit):
            raise self._limit("max_output_bytes", f"output exceeds {limit} bytes", operation, step)

    def require_operation(self, operation: str, step_index: int) -> None:
        if operation in NETWORK_OPERATIONS and not self.policy.allow_network:
            raise OperationPermissionError(
                operation,
                "network access is not permitted by the execution policy",
                step_index=step_index,
                branch_path=self.branch_path,
                execution_id=self.execution_id,
            )

    def record(
        self,
        operation: str,
        step_index: int,
        before: Data,
        after: Data | None,
        started: float,
        error: BaseException | None,
    ) -> None:
        if not self.trace_enabled:
            return
        cost = _TRACE_ENTRY_OVERHEAD + len(operation)
        limit = self.policy.max_trace_bytes
        with self._lock:
            if limit is not None and self._trace_bytes + cost > limit:
                raise self._limit(
                    "max_trace_bytes", f"trace exceeds {limit} bytes", operation, step_index
                )
            self._trace_bytes += cost
            self.trace.append(
                TraceStep(
                    operation=operation,
                    step_index=step_index,
                    branch_path=self.branch_path,
                    input_type="bytes" if isinstance(before, bytes) else "string",
                    output_type=(
                        "none"
                        if after is None
                        else "bytes"
                        if isinstance(after, bytes)
                        else "string"
                    ),
                    input_size=data_size(before),
                    output_size=0 if after is None else data_size(after),
                    duration_ms=(perf_counter() - started) * 1000,
                    error=type(error).__name__ if error is not None else None,
                )
            )


# Scoped (not global) holder so operation implementations, which only receive
# ``(value, args)``, can honour the policy of the execution that invoked them.
_active_policy: contextvars.ContextVar[ExecutionPolicy | None] = contextvars.ContextVar(
    "pychef_active_policy", default=None
)


@contextmanager
def active_policy(policy: ExecutionPolicy) -> Iterator[None]:
    token = _active_policy.set(policy)
    try:
        yield
    finally:
        _active_policy.reset(token)


def current_policy() -> ExecutionPolicy | None:
    """Policy of the running execution, or ``None`` outside of one (legacy direct calls)."""
    return _active_policy.get()
