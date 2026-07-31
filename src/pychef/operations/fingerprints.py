"""Pure-Python SSH HASSH and TLS JA3/JA3S fingerprint operations."""

from __future__ import annotations

import hashlib

from ..registry import operation
from ..types import Args, Data
from ._utils import arg
from .modern_ciphers import _formatted_input

_GREASE = frozenset(range(0x0A0A, 0xFAFB, 0x1010))


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, length: int) -> bytes:
        if length < 0 or length > self.remaining:
            raise ValueError("Not enough input data.")
        result = self.data[self.position : self.position + length]
        self.position += length
        return result

    def integer(self, length: int) -> int:
        return int.from_bytes(self.take(length), "big")


def _md5(value: str) -> str:
    return hashlib.new("md5", value.encode()).hexdigest()


def _ssh_string(reader: _Reader) -> str:
    return reader.take(reader.integer(4)).decode("latin-1")


def _hassh(value: Data, args: Args, *, server: bool) -> str:
    input_format = str(arg(args, 0, "Hex"))
    output_format = str(arg(args, 1, "Hash digest"))
    data = _formatted_input(value, input_format)
    reader = _Reader(data)
    packet_length = reader.integer(4)
    if len(data) != packet_length + 4:
        raise ValueError("Incorrect packet length.")
    padding_length = reader.integer(1)
    if reader.integer(1) != 20:
        raise ValueError("Not a Key Exchange Init.")
    reader.take(16)
    algorithms = [_ssh_string(reader) for _ in range(10)]
    reader.take(1)
    reader.take(4)
    reader.take(padding_length)
    kex = algorithms[0]
    if server:
        encryption, mac, compression = algorithms[3], algorithms[5], algorithms[7]
        direction = "Server to Client"
    else:
        encryption, mac, compression = algorithms[2], algorithms[4], algorithms[6]
        direction = "Client to Server"
    algorithms_string = ";".join((kex, encryption, mac, compression))
    digest = _md5(algorithms_string)
    if output_format == "HASSH algorithms string":
        return algorithms_string
    if output_format == "Full details":
        return (
            f"Hash digest:\n{digest}\n\n"
            f"Full HASSH algorithms string:\n{algorithms_string}\n\n"
            f"Key Exchange Algorithms:\n{kex}\n"
            f"Encryption Algorithms {direction}:\n{encryption}\n"
            f"MAC Algorithms {direction}:\n{mac}\n"
            f"Compression Algorithms {direction}:\n{compression}"
        )
    return digest


@operation("HASSH Client Fingerprint", category="Crypto")
def hassh_client(value: Data, args: Args) -> Data:
    return _hassh(value, args, server=False)


@operation("HASSH Server Fingerprint", category="Crypto")
def hassh_server(value: Data, args: Args) -> Data:
    return _hassh(value, args, server=True)


def _ja3_segment(data: bytes, size: int) -> str:
    reader = _Reader(data)
    values = []
    while reader.remaining:
        value = reader.integer(size)
        if value not in _GREASE:
            values.append(str(value))
    return "-".join(values)


def _tls_record(value: Data, input_format: str, handshake_type: int) -> _Reader:
    data = _formatted_input(value, input_format)
    reader = _Reader(data)
    if reader.integer(1) != 0x16:
        raise ValueError("Not handshake data.")
    reader.take(2)
    if len(data) != reader.integer(2) + 5:
        raise ValueError("Incorrect handshake length.")
    if reader.integer(1) != handshake_type:
        name = "Client" if handshake_type == 1 else "Server"
        raise ValueError(f"Not a {name} Hello.")
    if len(data) != reader.integer(3) + 9:
        name = "Client" if handshake_type == 1 else "Server"
        raise ValueError(f"Not enough data in {name} Hello.")
    return reader


@operation("JA3 Fingerprint", category="Crypto")
def ja3(value: Data, args: Args) -> Data:
    output_format = str(arg(args, 1, "Hash digest"))
    reader = _tls_record(value, str(arg(args, 0, "Hex")), 1)
    version = reader.integer(2)
    reader.take(32)
    reader.take(reader.integer(1))
    ciphers = _ja3_segment(reader.take(reader.integer(2)), 2)
    reader.take(reader.integer(1))
    extension_reader = _Reader(reader.take(reader.integer(2)))
    extensions: list[str] = []
    curves = ""
    point_formats = ""
    while extension_reader.remaining:
        extension_type = extension_reader.integer(2)
        payload = extension_reader.take(extension_reader.integer(2))
        if extension_type == 0x0A:
            payload_reader = _Reader(payload)
            curves = _ja3_segment(payload_reader.take(payload_reader.integer(2)), 2)
        elif extension_type == 0x0B:
            payload_reader = _Reader(payload)
            point_formats = _ja3_segment(payload_reader.take(payload_reader.integer(1)), 1)
        if extension_type not in _GREASE:
            extensions.append(str(extension_type))
    extension_string = "-".join(extensions)
    ja3_string = f"{version},{ciphers},{extension_string},{curves},{point_formats}"
    digest = _md5(ja3_string)
    if output_format == "JA3 string":
        return ja3_string
    if output_format == "Full details":
        return (
            f"Hash digest:\n{digest}\n\nFull JA3 string:\n{ja3_string}\n\n"
            f"TLS Version:\n{version}\nCipher Suites:\n{ciphers}\n"
            f"Extensions:\n{extension_string}\nElliptic Curves:\n{curves}\n"
            f"Elliptic Curve Point Formats:\n{point_formats}"
        )
    return digest


@operation("JA3S Fingerprint", category="Crypto")
def ja3s(value: Data, args: Args) -> Data:
    output_format = str(arg(args, 1, "Hash digest"))
    reader = _tls_record(value, str(arg(args, 0, "Hex")), 2)
    version = reader.integer(2)
    reader.take(32)
    reader.take(reader.integer(1))
    cipher = reader.integer(2)
    reader.take(1)
    extension_reader = _Reader(reader.take(reader.integer(2)))
    extensions = []
    while extension_reader.remaining:
        extension_type = extension_reader.integer(2)
        extension_reader.take(extension_reader.integer(2))
        extensions.append(str(extension_type))
    extension_string = "-".join(extensions)
    ja3s_string = f"{version},{cipher},{extension_string}"
    digest = _md5(ja3s_string)
    if output_format == "JA3S string":
        return ja3s_string
    if output_format == "Full details":
        return (
            f"Hash digest:\n{digest}\n\nFull JA3S string:\n{ja3s_string}\n\n"
            f"TLS Version:\n{version}\nCipher Suite:\n{cipher}\nExtensions:\n{extension_string}"
        )
    return digest


_TLS_VERSION_LABELS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0200: "s2",
    0x0100: "s1",
}


def _extensions(reader: _Reader) -> list[tuple[int, bytes]]:
    if not reader.remaining:
        return []
    extension_reader = _Reader(reader.take(reader.integer(2)))
    output = []
    while extension_reader.remaining:
        extension_type = extension_reader.integer(2)
        output.append((extension_type, extension_reader.take(extension_reader.integer(2))))
    return output


def _highest_version(legacy_version: int, extensions: list[tuple[int, bytes]]) -> int:
    for extension_type, payload in extensions:
        if extension_type != 0x002B:
            continue
        if len(payload) == 2:
            return int.from_bytes(payload, "big")
        versions = payload[1 : 1 + payload[0]] if payload else b""
        candidates = [
            int.from_bytes(versions[position : position + 2], "big")
            for position in range(0, len(versions) - 1, 2)
        ]
        candidates = [version for version in candidates if version not in _GREASE]
        return max(candidates, default=0)
    return legacy_version


def _first_alpn(extensions: list[tuple[int, bytes]]) -> bytes:
    for extension_type, payload in extensions:
        if extension_type != 0x0010 or len(payload) < 3:
            continue
        value_length = payload[2]
        return payload[3 : 3 + value_length]
    return b""


def _alpn_fingerprint(value: bytes) -> str:
    if not value:
        return "00"
    first, last = value[0], value[-1]
    if chr(first).isalnum() and first < 128 and chr(last).isalnum() and last < 128:
        return chr(first) + chr(last)
    return f"{first:02x}"[0] + f"{last:02x}"[1]


def _sha256_prefix(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _client_hello(value: Data, input_format: str) -> tuple[int, list[int], list[tuple[int, bytes]]]:
    reader = _tls_record(value, input_format, 1)
    version = reader.integer(2)
    reader.take(32)
    reader.take(reader.integer(1))
    cipher_data = reader.take(reader.integer(2))
    if len(cipher_data) % 2:
        raise ValueError("Invalid TLS cipher suite list.")
    ciphers = [
        int.from_bytes(cipher_data[position : position + 2], "big")
        for position in range(0, len(cipher_data), 2)
    ]
    reader.take(reader.integer(1))
    extensions = _extensions(reader)
    return version, ciphers, extensions


def _server_hello(value: Data, input_format: str) -> tuple[int, int, list[tuple[int, bytes]]]:
    reader = _tls_record(value, input_format, 2)
    version = reader.integer(2)
    reader.take(32)
    reader.take(reader.integer(1))
    cipher = reader.integer(2)
    reader.take(1)
    return version, cipher, _extensions(reader)


def _ja4_values(value: Data, input_format: str) -> dict[str, str]:
    try:
        legacy_version, ciphers, extensions = _client_hello(value, input_format)
    except ValueError as exc:
        raise ValueError(
            f"Data is not a valid TLS Client Hello. QUIC is not yet supported.\n{exc}"
        ) from exc
    version = _TLS_VERSION_LABELS.get(_highest_version(legacy_version, extensions), "00")
    sni = "d" if any(extension_type == 0 for extension_type, _ in extensions) else "i"
    ciphers = [cipher for cipher in ciphers if cipher not in _GREASE]
    extension_count = sum(extension_type not in _GREASE for extension_type, _ in extensions)
    alpn = _alpn_fingerprint(_first_alpn(extensions))
    prefix = f"t{version}{sni}{min(len(ciphers), 99):02d}{min(extension_count, 99):02d}{alpn}"

    original_cipher_items = [f"{cipher:04x}" for cipher in ciphers]
    sorted_cipher_raw = ",".join(sorted(original_cipher_items))
    original_cipher_raw = ",".join(original_cipher_items)

    original_extension_items = [
        f"{extension_type:04x}" for extension_type, _ in extensions if extension_type not in _GREASE
    ]
    signature_algorithms = ""
    for extension_type, payload in extensions:
        if extension_type == 0x000D:
            raw = payload[2:].hex()
            signature_algorithms = ",".join(
                raw[position : position + 4] for position in range(0, len(raw), 4)
            )
            break
    sorted_extension_items = sorted(
        item for item in original_extension_items if item not in {"0000", "0010"}
    )
    sorted_extension_raw = ",".join(sorted_extension_items) + "_" + signature_algorithms
    original_extension_raw = ",".join(original_extension_items) + "_" + signature_algorithms
    return {
        "JA4": (
            f"{prefix}_{_sha256_prefix(sorted_cipher_raw)}_{_sha256_prefix(sorted_extension_raw)}"
        ),
        "JA4_o": (
            f"{prefix}_{_sha256_prefix(original_cipher_raw)}_"
            f"{_sha256_prefix(original_extension_raw)}"
        ),
        "JA4_r": f"{prefix}_{sorted_cipher_raw}_{sorted_extension_raw}",
        "JA4_ro": f"{prefix}_{original_cipher_raw}_{original_extension_raw}",
    }


def _ja4s_values(value: Data, input_format: str) -> dict[str, str]:
    try:
        legacy_version, cipher, extensions = _server_hello(value, input_format)
    except ValueError as exc:
        raise ValueError(
            f"Data is not a valid TLS Server Hello. QUIC is not yet supported.\n{exc}"
        ) from exc
    version = _TLS_VERSION_LABELS.get(_highest_version(legacy_version, extensions), "00")
    alpn = _alpn_fingerprint(_first_alpn(extensions))
    prefix = f"t{version}{min(len(extensions), 99):02d}{alpn}_{cipher:04x}"
    extension_raw = ",".join(f"{extension_type:04x}" for extension_type, _ in extensions)
    return {
        "JA4S": f"{prefix}_{_sha256_prefix(extension_raw)}",
        "JA4S_r": f"{prefix}_{extension_raw}",
    }


@operation("JA4 Fingerprint", category="Crypto")
def ja4(value: Data, args: Args) -> Data:
    output_format = str(arg(args, 1, "JA4"))
    values = _ja4_values(value, str(arg(args, 0, "Hex")))
    if output_format == "JA4":
        return values["JA4"]
    if output_format == "JA4 Original Rendering":
        return values["JA4_o"]
    if output_format == "JA4 Raw":
        return values["JA4_r"]
    if output_format == "JA4 Raw Original Rendering":
        return values["JA4_ro"]
    return (
        f"JA4:    {values['JA4']}\nJA4_o:  {values['JA4_o']}\n"
        f"JA4_r:  {values['JA4_r']}\nJA4_ro: {values['JA4_ro']}"
    )


@operation("JA4Server Fingerprint", category="Crypto")
def ja4_server(value: Data, args: Args) -> Data:
    output_format = str(arg(args, 1, "JA4S"))
    values = _ja4s_values(value, str(arg(args, 0, "Hex")))
    if output_format == "JA4S":
        return values["JA4S"]
    if output_format == "JA4S Raw":
        return values["JA4S_r"]
    return f"JA4S:   {values['JA4S']}\nJA4S_r: {values['JA4S_r']}"
