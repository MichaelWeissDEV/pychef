"""Pure-Python packet header and compact binary protocol parsers."""

from __future__ import annotations

import html
import ipaddress
import json
import re

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int


def _input_bytes(value: Data, input_format: str) -> bytes:
    if input_format == "Hex":
        return bytes.fromhex(re.sub(r"\s+", "", to_text(value)))
    if input_format == "Base64":
        import base64

        return base64.b64decode(to_bytes(value))
    return to_bytes(value)


@operation("Strip IPv4 header", category="Networking")
def strip_ipv4(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    if len(data) < 20:
        raise ValueError("need at least 20 bytes for an IPv4 header")
    header_length = (data[0] & 0x0F) * 4
    if data[0] >> 4 != 4 or header_length < 20 or header_length > len(data):
        raise ValueError("invalid IPv4 header")
    return data[header_length:]


@operation("Strip TCP header", category="Networking")
def strip_tcp(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    if len(data) < 20:
        raise ValueError("Need at least 20 bytes for a TCP Header")
    header_length = (data[12] >> 4) * 4
    if header_length > len(data):
        raise ValueError("Input length is less than data offset")
    return data[header_length:]


@operation("Strip UDP header", category="Networking")
def strip_udp(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    if len(data) < 8:
        raise ValueError("Need 8 bytes for a UDP Header")
    return data[8:]


@operation("Parse IPv4 header", category="Networking")
def parse_ipv4(value: Data, args: Args) -> Data:
    data = _input_bytes(value, str(arg(args, 0, "Hex")))
    output_format = str(arg(args, 1, "Text output"))
    if len(data) < 20:
        return b"" if output_format == "Data (raw)" else ""
    header_length = (data[0] & 0xF) * 4
    payload = data[header_length:]
    if output_format == "Data (raw)":
        return payload
    if output_format == "Packet data":
        return payload.decode("utf-8", "replace")
    source = ipaddress.IPv4Address(data[12:16])
    destination = ipaddress.IPv4Address(data[16:20])
    return (
        f"Version: {data[0] >> 4}\nHeader length: {header_length} bytes"
        f"\nTotal length: {int.from_bytes(data[2:4], 'big')}"
        f"\nProtocol: {data[9]}\nSource: {source}\nDestination: {destination}"
        f"\nData:\n{payload.hex(' ')}"
    )


@operation("Parse TCP", category="Networking")
def parse_tcp(value: Data, args: Args) -> Data:
    data = _input_bytes(value, str(arg(args, 0, "Hex")))
    if len(data) < 20:
        raise ValueError("Need at least 20 bytes for a TCP Header")
    header_length = (data[12] >> 4) * 4
    payload = data[header_length:]
    flags = data[13]
    packet: dict[str, object] = {
        "Source port": int.from_bytes(data[:2], "big"),
        "Destination port": int.from_bytes(data[2:4], "big"),
        "Sequence number": int.from_bytes(data[4:8], "big"),
        "Acknowledgement number": int.from_bytes(data[8:12], "big"),
        "Data offset": f"{data[12] >> 4} ({header_length} bytes)",
        "Flags": {
            "NS": data[12] & 1,
            "CWR": (flags >> 7) & 1,
            "ECE": (flags >> 6) & 1,
            "URG": (flags >> 5) & 1,
            "ACK": (flags >> 4) & 1,
            "PSH": (flags >> 3) & 1,
            "RST": (flags >> 2) & 1,
            "SYN": (flags >> 1) & 1,
            "FIN": flags & 1,
        },
        "Window size": f"{int.from_bytes(data[14:16], 'big')} "
        f"(Scaled: {int.from_bytes(data[14:16], 'big')})",
        "Checksum": f"0x{data[16:18].hex()}",
        "Urgent pointer": f"0x{data[18:20].hex()}",
    }
    if payload:
        packet["Data"] = f"0x{payload.hex()}"
    return json.dumps(packet, separators=(",", ":"))


@operation("Parse UDP", category="Networking")
def parse_udp(value: Data, args: Args) -> Data:
    data = _input_bytes(value, str(arg(args, 0, "Hex")))
    if len(data) < 8:
        raise ValueError("Need 8 bytes for a UDP Header")
    length = int.from_bytes(data[4:6], "big")
    packet: dict[str, object] = {
        "Source port": int.from_bytes(data[:2], "big"),
        "Destination port": int.from_bytes(data[2:4], "big"),
        "Length": length,
        "Checksum": f"0x{data[6:8].hex()}",
    }
    if payload := data[8:length]:
        packet["Data"] = f"0x{payload.hex()}"
    return json.dumps(packet, separators=(",", ":"))


@operation("Parse Ethernet frame", category="Networking")
def parse_ethernet(value: Data, args: Args) -> Data:
    data = _input_bytes(value, str(arg(args, 0, "Hex")))
    output_format = str(arg(args, 1, "Text output"))
    if len(data) < 14:
        raise ValueError("Ethernet frame is shorter than 14 bytes")
    destination = data[:6].hex(":")
    source = data[6:12].hex(":")
    ether_type = int.from_bytes(data[12:14], "big")
    position = 14
    vlans: list[int] = []
    while ether_type in {0x8100, 0x88A8} and len(data) >= position + 4:
        tag = int.from_bytes(data[position : position + 2], "big")
        vlans.append(tag & 0xFFF)
        ether_type = int.from_bytes(data[position + 2 : position + 4], "big")
        position += 4
    payload = data[position:]
    if output_format == "Packet data":
        return html.escape(payload.decode("utf-8", "replace"))
    if output_format == "Data (raw)":
        return payload
    output = f"Source MAC: {source}\nDestination MAC: {destination}\n"
    if vlans:
        output += "VLAN: " + ", ".join(map(str, vlans)) + "\n"
    return output + "Data:\n" + payload.hex(" ")


@operation("Parse TLV", category="Serialisation")
def parse_tlv(value: Data, args: Args) -> str:
    key_length = require_int(arg(args, 0, 0), name="key length")
    length_size = require_int(arg(args, 1, 1), name="length size")
    ber = bool(arg(args, 2, False))
    data = to_bytes(value)
    position = 0
    entries: list[dict[str, object]] = []
    while position < len(data):
        entry: dict[str, object] = {}
        if key_length:
            entry["key"] = list(data[position : position + key_length])
            position += key_length
        if position >= len(data):
            raise ValueError("truncated TLV length")
        if ber and data[position] & 0x80:
            octets = data[position] & 0x7F
            position += 1
            length = int.from_bytes(data[position : position + octets], "big")
            position += octets
        else:
            size = 1 if ber else length_size
            length = int.from_bytes(data[position : position + size], "big")
            position += size
        if position + length > len(data):
            raise ValueError("TLV value exceeds input length")
        entry["length"] = length
        entry["value"] = list(data[position : position + length])
        position += length
        entries.append(entry)
    return json.dumps(entries, indent=4)


@operation("Parse UNIX file permissions", category="Operating system")
def parse_unix_permissions(value: Data, _args: Args) -> str:
    text = to_text(value).strip()
    if re.fullmatch(r"[0-7]{3,4}", text):
        mode = int(text, 8)
    elif re.fullmatch(r"[-dlcbps][rwxStTs-]{9}", text):
        mode = 0
        for index, character in enumerate(text[-9:]):
            if character != "-":
                mode |= 1 << (8 - index)
    else:
        raise ValueError("invalid UNIX permissions")
    symbolic = ""
    for shift in (6, 3, 0):
        digit = (mode >> shift) & 7
        symbolic += "r" if digit & 4 else "-"
        symbolic += "w" if digit & 2 else "-"
        symbolic += "x" if digit & 1 else "-"
    return f"Octal: {mode & 0o777:03o}\nSymbolic: {symbolic}"


@operation("Parse colour code", category="Data format")
def parse_colour(value: Data, _args: Args) -> str:
    text = to_text(value).strip()
    if match := re.fullmatch(r"#?([0-9a-fA-F]{6})([0-9a-fA-F]{2})?", text):
        red, green, blue = bytes.fromhex(match.group(1))
        alpha = int(match.group(2), 16) if match.group(2) else 255
    elif match := re.fullmatch(r"rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)", text):
        red, green, blue = map(int, match.group(1, 2, 3))
        alpha = round(float(match.group(4)) * 255) if match.group(4) else 255
    else:
        raise ValueError("unsupported colour format")
    return (
        f"Hex: #{red:02x}{green:02x}{blue:02x}{alpha:02x}\n"
        f"RGBA: rgba({red}, {green}, {blue}, {alpha / 255:g})"
    )


@operation("Hex to Object Identifier", category="Serialisation")
def hex_to_oid(value: Data, _args: Args) -> str:
    data = bytes.fromhex(re.sub(r"\s+", "", to_text(value)))
    if not data:
        return ""
    components = [data[0] // 40, data[0] % 40]
    number = 0
    for byte in data[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            components.append(number)
            number = 0
    if number:
        raise ValueError("truncated object identifier")
    return ".".join(map(str, components))


@operation("Object Identifier to Hex", category="Serialisation")
def oid_to_hex(value: Data, _args: Args) -> str:
    components = [int(part) for part in to_text(value).strip().split(".")]
    if len(components) < 2:
        raise ValueError("OID needs at least two components")
    output = bytearray([components[0] * 40 + components[1]])
    for component in components[2:]:
        encoded = [component & 0x7F]
        component >>= 7
        while component:
            encoded.append((component & 0x7F) | 0x80)
            component >>= 7
        output.extend(reversed(encoded))
    return output.hex()


@operation("Hex to PEM", category="Public Key")
def hex_to_pem(value: Data, args: Args) -> str:
    import base64

    label = str(arg(args, 0, "CERTIFICATE"))
    encoded = base64.b64encode(bytes.fromhex(re.sub(r"\s+", "", to_text(value)))).decode()
    lines = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----"


@operation("PEM to Hex", category="Public Key")
def pem_to_hex(value: Data, _args: Args) -> str:
    import base64

    body = re.sub(r"-----[^-]+-----|\s+", "", to_text(value))
    return base64.b64decode(body).hex()


@operation("Parse SSH Host Key", category="Public Key")
def parse_ssh_host_key(value: Data, args: Args) -> str:
    import base64

    text = to_text(value).strip()
    input_format = str(arg(args, 0, "Auto"))
    if match := re.match(r"^(?:ssh|ecdsa-sha2)\S+\s+(\S+)", text):
        text = match.group(1)
    if input_format == "Auto":
        input_format = "Hex" if re.fullmatch(r"(?:[0-9a-fA-F]{2}[ ,;:]?)+", text) else "Base64"
    if input_format == "Hex":
        data = bytes.fromhex(re.sub(r"[ ,;:]", "", text))
    elif input_format == "Base64":
        data = base64.b64decode(text)
    else:
        raise ValueError("invalid SSH host key input format")
    fields: list[bytes] = []
    position = 0
    while position + 4 <= len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        position += 4
        if length <= 0 or position + length > len(data):
            break
        fields.append(data[position : position + length])
        position += length
    if not fields:
        raise ValueError("SSH host key contains no fields")
    key_type = fields[0].decode("ascii", "replace")
    output = f"Key type: {key_type}"
    if key_type == "ssh-rsa" and len(fields) >= 3:
        return output + f"\nExponent: 0x{fields[1].hex()}\nModulus: 0x{fields[2].hex()}"
    if key_type == "ssh-dss" and len(fields) >= 5:
        labels = ("p", "q", "g", "y")
        return output + "".join(
            f"\n{label}: 0x{field.hex()}" for label, field in zip(labels, fields[1:5], strict=True)
        )
    if key_type.startswith("ecdsa-sha2") and len(fields) >= 3:
        return (
            output
            + f"\nCurve: {fields[1].decode('ascii', 'replace')}"
            + f"\nPoint: 0x{fields[2].hex()}"
        )
    if key_type == "ssh-ed25519" and len(fields) >= 2:
        return output + f"\nx: 0x{fields[1].hex()}"
    parameters = ",".join(field.hex() for field in fields[1:])
    return output + f"\nUnsupported key type.\nParameters: {parameters}"


_ASN1_TAG_NAMES = {
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BITSTRING",
    4: "OCTETSTRING",
    5: "NULL",
    6: "OBJECTIDENTIFIER",
    10: "ENUMERATED",
    12: "UTF8STRING",
    19: "PRINTABLESTRING",
    22: "IA5STRING",
    23: "UTCTIME",
    24: "GENERALIZEDTIME",
    48: "SEQUENCE",
    49: "SET",
}


def _asn1_dump(data: bytes, position: int, indent: str = "") -> tuple[list[str], int]:
    if position >= len(data):
        return [], position
    tag = data[position]
    position += 1
    if position >= len(data):
        return [f"{indent}UNKNOWN({tag})"], position
    first_length = data[position]
    position += 1
    if first_length & 0x80:
        octets = first_length & 0x7F
        if position + octets > len(data):
            return [f"{indent}UNKNOWN({tag})"], len(data)
        length = int.from_bytes(data[position : position + octets], "big")
        position += octets
    else:
        length = first_length
    content = data[position : position + length]
    end = min(position + length, len(data))
    name = _ASN1_TAG_NAMES.get(tag, f"UNKNOWN({tag})")
    if tag & 0x20 and content:
        lines = [name]
        child_position = position
        while child_position < end:
            children, child_position = _asn1_dump(data, child_position, indent + "  ")
            lines.extend(children)
        return lines, end
    return [f"{indent}{name} {content.hex()}".rstrip()], end


@operation("Parse ASN.1 hex string", category="Public Key")
def parse_asn1_hex(value: Data, args: Args) -> str:
    data = bytes.fromhex(re.sub(r"\s+", "", to_text(value)))
    start = require_int(arg(args, 0, 0), name="starting index")
    lines, _position = _asn1_dump(data, start)
    return "\n".join(lines) + ("\n" if lines else "")


class _TLSCursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def read(self, length: int) -> bytes:
        start = self.position
        self.position += length
        return self.data[start : start + length]

    def integer(self, length: int) -> int:
        value = self.read(length)
        return int.from_bytes(value, "big") if len(value) == length else 0

    def hexadecimal(self, length: int) -> str:
        value = self.read(length)
        return f"0x{value.hex()}" if len(value) == length else ""

    def sized_hexadecimal(self, prefix_length: int) -> str:
        length = self.integer(prefix_length)
        return self.hexadecimal(length) if length else ""


def _tls_list(cursor: _TLSCursor, prefix_length: int, item_length: int) -> dict[str, object]:
    length = cursor.integer(prefix_length)
    if not length:
        return {}
    content = cursor.read(length)
    result: dict[str, object] = {"length": length}
    if len(content) < length:
        result["truncated"] = True
    result["values"] = [
        f"0x{content[position : position + item_length].hex()}"
        for position in range(0, len(content), item_length)
        if len(content[position : position + item_length]) == item_length
    ]
    return result


def _tls_extensions(cursor: _TLSCursor) -> dict[str, object]:
    length = cursor.integer(2)
    if not length:
        return {}
    content = cursor.read(length)
    output: dict[str, object] = {"length": length}
    if len(content) < length:
        output["truncated"] = True
    values: list[dict[str, object]] = []
    extensions = _TLSCursor(content)
    while extensions.position + 4 <= len(content):
        extension: dict[str, object] = {"type": extensions.hexadecimal(2)}
        extension_length = extensions.integer(2)
        extension["length"] = extension_length
        extension_value = extensions.read(extension_length)
        if len(extension_value) < extension_length:
            extension["truncated"] = True
        if extension_value:
            extension["value"] = f"0x{extension_value.hex()}"
        values.append(extension)
    output["values"] = values
    return output


def _tls_client_hello(content: bytes) -> dict[str, object]:
    cursor = _TLSCursor(content)
    output: dict[str, object] = {
        "clientVersion": cursor.hexadecimal(2),
        "random": cursor.hexadecimal(32),
    }
    session_id = cursor.sized_hexadecimal(1)
    if session_id:
        output["sessionID"] = session_id
    output["cipherSuites"] = _tls_list(cursor, 2, 2)
    output["compressionMethods"] = _tls_list(cursor, 1, 1)
    output["extensions"] = _tls_extensions(cursor)
    return output


def _tls_server_hello(content: bytes) -> dict[str, object]:
    cursor = _TLSCursor(content)
    output: dict[str, object] = {
        "serverVersion": cursor.hexadecimal(2),
        "random": cursor.hexadecimal(32),
    }
    session_id = cursor.sized_hexadecimal(1)
    if session_id:
        output["sessionID"] = session_id
    output["cipherSuite"] = cursor.hexadecimal(2)
    output["compressionMethod"] = cursor.hexadecimal(1)
    output["extensions"] = _tls_extensions(cursor)
    return output


@operation("Parse TLS record", category="Networking")
def parse_tls_record(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    position = 0
    records: list[dict[str, object]] = []
    content_types = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
    handshake_types = {
        0: "hello_request",
        1: "client_hello",
        2: "server_hello",
        4: "new_session_ticket",
        11: "certificate",
        12: "server_key_exchange",
        13: "certificate_request",
        14: "server_hello_done",
        15: "certificate_verify",
        16: "client_key_exchange",
        20: "finished",
    }
    while position + 5 <= len(data):
        kind = data[position]
        length = int.from_bytes(data[position + 3 : position + 5], "big")
        start = position + 5
        end = start + length
        content = data[start : min(end, len(data))]
        record: dict[str, object] = {
            "type": content_types.get(kind, str(kind)),
            "version": f"0x{data[position + 1 : position + 3].hex()}",
            "length": length,
        }
        if len(content) < length:
            record["truncated"] = True
        if kind == 22 and content:
            handshake_kind = content[0]
            record["handshakeType"] = handshake_types.get(handshake_kind, str(handshake_kind))
            if len(content) >= 4:
                handshake_length = int.from_bytes(content[1:4], "big")
                if handshake_length + 4 != length:
                    record["handshakeType"] = "finished"
                    record["handshakeValue"] = f"0x{content.hex()}"
                else:
                    handshake_content = content[4 : 4 + handshake_length]
                    if handshake_content:
                        if handshake_kind == 1:
                            record.update(_tls_client_hello(handshake_content))
                        elif handshake_kind == 2:
                            record.update(_tls_server_hello(handshake_content))
                        else:
                            record["handshakeValue"] = f"0x{handshake_content.hex()}"
        elif content:
            record["value"] = f"0x{content.hex()}"
        records.append(record)
        position = end
    return json.dumps(records, separators=(",", ":"))
