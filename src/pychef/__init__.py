"""Pure-Python CyberChef-compatible data transformations."""

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _distribution_version

from .compatibility import CompatibilityReport, compatibility_report
from .ctf import (
    aes_decrypt,
    aes_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    chunks,
    cyclic,
    cyclic_find,
    decode_bytes,
    digest,
    digests,
    encode_bytes,
    flat,
    hexdump,
    md5,
    p8,
    p16,
    p16be,
    p16le,
    p32,
    p32be,
    p32le,
    p64,
    p64be,
    p64le,
    pack,
    rol,
    ror,
    sha1,
    sha256,
    sha512,
    swap_endian,
    u8,
    u16,
    u16be,
    u16le,
    u32,
    u32be,
    u32le,
    u64,
    u64be,
    u64le,
    unpack,
    xor_bytes,
)
from .errors import (
    ExecutionLimitError,
    ExecutionTimeoutError,
    InvalidOperationArgumentsError,
    OperationError,
    OperationPermissionError,
    PyChefError,
    RecipeError,
    UnknownOperationError,
)
from .execution import ExecutionContext, ExecutionPolicy, NetworkPolicy, normalize_host
from .packets import (
    json_safe,
    packet_json,
    parse_arp_packet,
    parse_capture,
    parse_dns_message,
    parse_ethernet_frame,
    parse_icmp_message,
    parse_ipv4_packet,
    parse_ipv6_packet,
    parse_packet,
    parse_pcap,
    parse_pcapng,
    parse_tcp_segment,
    parse_udp_datagram,
    read_capture,
)
from .pipeline import Pipeline, PipelineTrace
from .recipe import Chef, Recipe, bake
from .registry import Operation, OperationRegistry, registry
from .spec import OperationArgSpec, OperationSpec, get_operation_spec, list_operation_specs
from .types import BakeResult, Data, RecipeConfig, RecipeStep, TraceStep
from .worker import IsolatedWorker, bake_isolated

__all__ = [
    "BakeResult",
    "Chef",
    "CompatibilityReport",
    "Data",
    "ExecutionContext",
    "ExecutionLimitError",
    "ExecutionPolicy",
    "ExecutionTimeoutError",
    "InvalidOperationArgumentsError",
    "IsolatedWorker",
    "NetworkPolicy",
    "Operation",
    "OperationArgSpec",
    "OperationError",
    "OperationPermissionError",
    "OperationRegistry",
    "OperationSpec",
    "Pipeline",
    "PipelineTrace",
    "PyChefError",
    "Recipe",
    "RecipeConfig",
    "RecipeError",
    "RecipeStep",
    "TraceStep",
    "UnknownOperationError",
    "aes_decrypt",
    "aes_encrypt",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "bake",
    "bake_isolated",
    "chunks",
    "compatibility_report",
    "cyclic",
    "cyclic_find",
    "decode_bytes",
    "digest",
    "digests",
    "encode_bytes",
    "flat",
    "get_operation_spec",
    "hexdump",
    "json_safe",
    "list_operation_specs",
    "list_operations",
    "md5",
    "normalize_host",
    "p8",
    "p16",
    "p16be",
    "p16le",
    "p32",
    "p32be",
    "p32le",
    "p64",
    "p64be",
    "p64le",
    "pack",
    "packet_json",
    "parse_arp_packet",
    "parse_capture",
    "parse_dns_message",
    "parse_ethernet_frame",
    "parse_icmp_message",
    "parse_ipv4_packet",
    "parse_ipv6_packet",
    "parse_packet",
    "parse_pcap",
    "parse_pcapng",
    "parse_tcp_segment",
    "parse_udp_datagram",
    "read_capture",
    "registry",
    "rol",
    "ror",
    "sha1",
    "sha256",
    "sha512",
    "swap_endian",
    "u8",
    "u16",
    "u16be",
    "u16le",
    "u32",
    "u32be",
    "u32le",
    "u64",
    "u64be",
    "u64le",
    "unpack",
    "xor_bytes",
]

try:
    __version__ = _distribution_version("cyberchef-py")
except _PackageNotFoundError:
    __version__ = "0+unknown"


def list_operations() -> tuple[str, ...]:
    """Return every registered operation name in stable alphabetical order."""
    return registry.names()


def __getattr__(name: str) -> object:
    if name == "operations":
        from . import operations

        return operations
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
