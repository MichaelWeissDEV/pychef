"""Dependency-free packet, PCAP, and PCAPNG decoding to Python dictionaries."""

from __future__ import annotations

import ipaddress
import json
import os
import struct
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .types import Data, to_bytes

_ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
    0x88A8: "802.1ad VLAN",
}
_IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}
_LINK_TYPES = {
    0: "NULL/Loopback",
    1: "Ethernet",
    101: "Raw IP",
    113: "Linux cooked v1",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked v2",
}


def _bytes(value: Data | bytearray | memoryview) -> bytes:
    return to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)


def _require(data: bytes, size: int, description: str) -> None:
    if len(data) < size:
        raise ValueError(f"truncated {description}: need {size} bytes, got {len(data)}")


def _mac(data: bytes) -> str:
    return data.hex(":")


def _parse_dns_name(
    data: bytes, offset: int, *, _visited: frozenset[int] = frozenset()
) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    visited = set(_visited)
    for _ in range(128):
        if cursor >= len(data):
            raise ValueError("truncated DNS name")
        length = data[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data) or pointer in visited:
                raise ValueError("invalid or cyclic DNS compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            suffix, _unused = _parse_dns_name(data, pointer, _visited=frozenset(visited))
            if suffix:
                labels.append(suffix)
            return ".".join(labels), next_offset
        if length & 0xC0:
            raise ValueError("invalid DNS label length")
        cursor += 1
        if length == 0:
            return ".".join(labels), next_offset if next_offset is not None else cursor
        if length > 63 or cursor + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(data[cursor : cursor + length].decode("ascii", "backslashreplace"))
        cursor += length
    raise ValueError("DNS name has too many labels")


def _dns_record(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    name, offset = _parse_dns_name(data, offset)
    _require(data[offset:], 10, "DNS resource record")
    record_type, record_class, ttl, length = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    end = offset + length
    if end > len(data):
        raise ValueError("DNS resource record exceeds message length")
    raw = data[offset:end]
    decoded: Any = raw
    if record_type == 1 and length == 4:
        decoded = str(ipaddress.IPv4Address(raw))
    elif record_type == 28 and length == 16:
        decoded = str(ipaddress.IPv6Address(raw))
    elif record_type in {2, 5, 12}:
        decoded, _unused = _parse_dns_name(data, offset)
    elif record_type == 15 and length >= 3:
        exchange, _unused = _parse_dns_name(data, offset + 2)
        decoded = {"preference": int.from_bytes(raw[:2], "big"), "exchange": exchange}
    elif record_type == 16:
        strings: list[str] = []
        position = 0
        while position < len(raw):
            text_length = raw[position]
            position += 1
            if position + text_length > len(raw):
                raise ValueError("truncated DNS TXT string")
            strings.append(raw[position : position + text_length].decode("utf-8", "replace"))
            position += text_length
        decoded = strings
    return {
        "name": name,
        "type": record_type,
        "class": record_class,
        "ttl": ttl,
        "data": decoded,
        "raw_data": raw,
    }, end


def parse_dns_message(value: Data | bytearray | memoryview) -> dict[str, Any]:
    """Decode a DNS wire message, including compressed names and common records."""
    data = _bytes(value)
    _require(data, 12, "DNS header")
    identifier, flags, question_count, answer_count, authority_count, additional_count = (
        struct.unpack_from("!HHHHHH", data)
    )
    offset = 12
    questions: list[dict[str, Any]] = []
    for _ in range(question_count):
        name, offset = _parse_dns_name(data, offset)
        _require(data[offset:], 4, "DNS question")
        query_type, query_class = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append({"name": name, "type": query_type, "class": query_class})

    def records(count: int) -> list[dict[str, Any]]:
        nonlocal offset
        output = []
        for _ in range(count):
            record, offset = _dns_record(data, offset)
            output.append(record)
        return output

    return {
        "protocol": "DNS",
        "id": identifier,
        "response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "authoritative": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "recursion_desired": bool(flags & 0x0100),
        "recursion_available": bool(flags & 0x0080),
        "response_code": flags & 0xF,
        "questions": questions,
        "answers": records(answer_count),
        "authorities": records(authority_count),
        "additionals": records(additional_count),
        "trailing_data": data[offset:],
    }


def _parse_http(data: bytes) -> dict[str, Any] | None:
    first_line = data.split(b"\r\n", 1)[0]
    methods = (
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
    )
    if not (first_line.startswith(b"HTTP/") or first_line.startswith(methods)):
        return None
    head, separator, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, colon, content = line.partition(b":")
        if colon:
            headers[name.decode("latin-1").strip()] = content.decode("latin-1").strip()
    return {
        "protocol": "HTTP",
        "start_line": lines[0].decode("latin-1", "replace"),
        "headers": headers,
        "body": body if separator else b"",
    }


def _parse_tls_record(data: bytes) -> dict[str, Any] | None:
    if len(data) < 5 or data[0] not in {20, 21, 22, 23, 24} or data[1] != 3:
        return None
    length = int.from_bytes(data[3:5], "big")
    if length > len(data) - 5:
        return None
    names = {
        20: "change_cipher_spec",
        21: "alert",
        22: "handshake",
        23: "application_data",
        24: "heartbeat",
    }
    result: dict[str, Any] = {
        "protocol": "TLS",
        "content_type": data[0],
        "content_type_name": names[data[0]],
        "version": f"{data[1]}.{data[2]}",
        "length": length,
        "data": data[5 : 5 + length],
    }
    if data[0] == 22 and length >= 4:
        result["handshake_type"] = data[5]
        result["handshake_length"] = int.from_bytes(data[6:9], "big")
    return result


def _application(payload: bytes, source_port: int, destination_port: int) -> dict[str, Any] | None:
    if 53 in {source_port, destination_port}:
        try:
            return parse_dns_message(payload)
        except ValueError:
            pass
    return _parse_http(payload) or _parse_tls_record(payload)


def _tcp_options(data: bytes) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    position = 0
    names = {
        0: "end",
        1: "nop",
        2: "mss",
        3: "window_scale",
        4: "sack_permitted",
        5: "sack",
        8: "timestamps",
    }
    while position < len(data):
        kind = data[position]
        if kind == 0:
            output.append({"kind": 0, "name": "end"})
            break
        if kind == 1:
            output.append({"kind": 1, "name": "nop"})
            position += 1
            continue
        if position + 2 > len(data):
            output.append({"kind": kind, "error": "truncated option length"})
            break
        length = data[position + 1]
        if length < 2 or position + length > len(data):
            output.append({"kind": kind, "error": "invalid option length"})
            break
        raw = data[position + 2 : position + length]
        option: dict[str, Any] = {"kind": kind, "name": names.get(kind, "unknown"), "data": raw}
        if kind == 2 and len(raw) == 2:
            option["value"] = int.from_bytes(raw, "big")
        elif kind == 3 and len(raw) == 1:
            option["value"] = raw[0]
        elif kind == 8 and len(raw) == 8:
            option["timestamp"] = int.from_bytes(raw[:4], "big")
            option["echo_reply"] = int.from_bytes(raw[4:], "big")
        output.append(option)
        position += length
    return output


def parse_tcp_segment(value: Data | bytearray | memoryview) -> dict[str, Any]:
    """Decode a TCP segment and common options/application payloads."""
    data = _bytes(value)
    _require(data, 20, "TCP header")
    source_port, destination_port, sequence, acknowledgement = struct.unpack_from("!HHII", data)
    header_length = (data[12] >> 4) * 4
    if header_length < 20 or header_length > len(data):
        raise ValueError("invalid TCP data offset")
    flags_value = ((data[12] & 1) << 8) | data[13]
    flag_masks = {
        "NS": 0x100,
        "CWR": 0x080,
        "ECE": 0x040,
        "URG": 0x020,
        "ACK": 0x010,
        "PSH": 0x008,
        "RST": 0x004,
        "SYN": 0x002,
        "FIN": 0x001,
    }
    payload = data[header_length:]
    result: dict[str, Any] = {
        "protocol": "TCP",
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence_number": sequence,
        "acknowledgement_number": acknowledgement,
        "header_length": header_length,
        "flags": {name: bool(flags_value & mask) for name, mask in flag_masks.items()},
        "flags_value": flags_value,
        "window_size": int.from_bytes(data[14:16], "big"),
        "checksum": int.from_bytes(data[16:18], "big"),
        "urgent_pointer": int.from_bytes(data[18:20], "big"),
        "options": _tcp_options(data[20:header_length]),
        "payload": payload,
    }
    if application := _application(payload, source_port, destination_port):
        result["application"] = application
    return result


def parse_udp_datagram(value: Data | bytearray | memoryview) -> dict[str, Any]:
    """Decode a UDP datagram and common application payloads."""
    data = _bytes(value)
    _require(data, 8, "UDP header")
    source_port, destination_port, length, checksum = struct.unpack_from("!HHHH", data)
    if length and length < 8:
        raise ValueError("invalid UDP length")
    if length > len(data):
        raise ValueError(f"truncated UDP datagram: declared {length}, captured {len(data)}")
    end = length or len(data)
    payload = data[8:end]
    result: dict[str, Any] = {
        "protocol": "UDP",
        "source_port": source_port,
        "destination_port": destination_port,
        "length": length,
        "checksum": checksum,
        "payload": payload,
        "trailing_data": data[end:],
    }
    if application := _application(payload, source_port, destination_port):
        result["application"] = application
    return result


def parse_icmp_message(
    value: Data | bytearray | memoryview, *, ipv6: bool = False
) -> dict[str, Any]:
    data = _bytes(value)
    _require(data, 4, "ICMP header")
    return {
        "protocol": "ICMPv6" if ipv6 else "ICMP",
        "type": data[0],
        "code": data[1],
        "checksum": int.from_bytes(data[2:4], "big"),
        "data": data[4:],
    }


def _transport(protocol: int, payload: bytes) -> dict[str, Any] | None:
    if protocol == 6:
        return parse_tcp_segment(payload)
    if protocol == 17:
        return parse_udp_datagram(payload)
    if protocol == 1:
        return parse_icmp_message(payload)
    if protocol == 58:
        return parse_icmp_message(payload, ipv6=True)
    return None


def parse_ipv4_packet(value: Data | bytearray | memoryview) -> dict[str, Any]:
    """Decode IPv4 and recursively decode its first-fragment transport payload."""
    data = _bytes(value)
    _require(data, 20, "IPv4 header")
    if data[0] >> 4 != 4:
        raise ValueError("packet is not IPv4")
    header_length = (data[0] & 0x0F) * 4
    if header_length < 20 or header_length > len(data):
        raise ValueError("invalid IPv4 header length")
    total_length = int.from_bytes(data[2:4], "big")
    if total_length < header_length:
        raise ValueError("invalid IPv4 total length")
    captured_end = min(total_length, len(data))
    flags_fragment = int.from_bytes(data[6:8], "big")
    fragment_offset = flags_fragment & 0x1FFF
    protocol = data[9]
    payload = data[header_length:captured_end]
    result: dict[str, Any] = {
        "protocol": "IPv4",
        "version": 4,
        "header_length": header_length,
        "dscp": data[1] >> 2,
        "ecn": data[1] & 3,
        "total_length": total_length,
        "identification": int.from_bytes(data[4:6], "big"),
        "flags": {
            "reserved": bool(flags_fragment & 0x8000),
            "dont_fragment": bool(flags_fragment & 0x4000),
            "more_fragments": bool(flags_fragment & 0x2000),
        },
        "fragment_offset": fragment_offset,
        "ttl": data[8],
        "ip_protocol": protocol,
        "ip_protocol_name": _IP_PROTOCOLS.get(protocol, "Unknown"),
        "header_checksum": int.from_bytes(data[10:12], "big"),
        "source": str(ipaddress.IPv4Address(data[12:16])),
        "destination": str(ipaddress.IPv4Address(data[16:20])),
        "options": data[20:header_length],
        "payload": payload,
        "truncated": total_length > len(data),
        "trailing_data": data[captured_end:],
    }
    if (
        fragment_offset == 0
        and not result["truncated"]
        and (transport := _transport(protocol, payload))
    ):
        result["transport"] = transport
    return result


def parse_ipv6_packet(value: Data | bytearray | memoryview) -> dict[str, Any]:
    """Decode IPv6, common extension headers, and its transport payload."""
    data = _bytes(value)
    _require(data, 40, "IPv6 header")
    if data[0] >> 4 != 6:
        raise ValueError("packet is not IPv6")
    first_word = int.from_bytes(data[:4], "big")
    payload_length = int.from_bytes(data[4:6], "big")
    next_header = data[6]
    captured_end = min(40 + payload_length, len(data)) if payload_length else len(data)
    position = 40
    extensions: list[dict[str, Any]] = []
    fragmented = False
    for _ in range(16):
        if next_header not in {0, 43, 44, 51, 60}:
            break
        if next_header == 44:
            if position + 8 > captured_end:
                raise ValueError("truncated IPv6 fragment header")
            following = data[position]
            fragment = int.from_bytes(data[position + 2 : position + 4], "big")
            extensions.append(
                {
                    "type": 44,
                    "name": "Fragment",
                    "next_header": following,
                    "fragment_offset": fragment >> 3,
                    "more_fragments": bool(fragment & 1),
                    "identification": int.from_bytes(data[position + 4 : position + 8], "big"),
                }
            )
            fragmented = fragment >> 3 != 0
            next_header = following
            position += 8
            continue
        if position + 2 > captured_end:
            raise ValueError("truncated IPv6 extension header")
        following = data[position]
        length = (data[position + 1] + 2) * 4 if next_header == 51 else (data[position + 1] + 1) * 8
        if length < 8 or position + length > captured_end:
            raise ValueError("invalid IPv6 extension header length")
        extensions.append(
            {
                "type": next_header,
                "next_header": following,
                "length": length,
                "data": data[position + 2 : position + length],
            }
        )
        next_header = following
        position += length
    else:
        raise ValueError("too many IPv6 extension headers")
    payload = data[position:captured_end]
    result: dict[str, Any] = {
        "protocol": "IPv6",
        "version": 6,
        "traffic_class": (first_word >> 20) & 0xFF,
        "flow_label": first_word & 0xFFFFF,
        "payload_length": payload_length,
        "next_header": next_header,
        "next_header_name": _IP_PROTOCOLS.get(next_header, "Unknown"),
        "hop_limit": data[7],
        "source": str(ipaddress.IPv6Address(data[8:24])),
        "destination": str(ipaddress.IPv6Address(data[24:40])),
        "extensions": extensions,
        "payload": payload,
        "truncated": bool(payload_length and 40 + payload_length > len(data)),
        "trailing_data": data[captured_end:],
    }
    if (
        not fragmented
        and not result["truncated"]
        and (transport := _transport(next_header, payload))
    ):
        result["transport"] = transport
    return result


def parse_arp_packet(value: Data | bytearray | memoryview) -> dict[str, Any]:
    data = _bytes(value)
    _require(data, 8, "ARP header")
    hardware_type, protocol_type, hardware_length, protocol_length, operation = struct.unpack_from(
        "!HHBBH", data
    )
    expected = 8 + 2 * hardware_length + 2 * protocol_length
    _require(data, expected, "ARP packet")
    position = 8
    sender_hardware = data[position : position + hardware_length]
    position += hardware_length
    sender_protocol = data[position : position + protocol_length]
    position += protocol_length
    target_hardware = data[position : position + hardware_length]
    position += hardware_length
    target_protocol = data[position : position + protocol_length]
    format_hardware = _mac if hardware_length == 6 else bytes.hex
    format_protocol = (
        (lambda item: str(ipaddress.IPv4Address(item)))
        if protocol_type == 0x0800 and protocol_length == 4
        else bytes.hex
    )
    return {
        "protocol": "ARP",
        "hardware_type": hardware_type,
        "protocol_type": protocol_type,
        "operation": operation,
        "sender_hardware": format_hardware(sender_hardware),
        "sender_protocol": format_protocol(sender_protocol),
        "target_hardware": format_hardware(target_hardware),
        "target_protocol": format_protocol(target_protocol),
        "trailing_data": data[expected:],
    }


def _network(ether_type: int, payload: bytes) -> dict[str, Any] | None:
    if ether_type == 0x0800:
        return parse_ipv4_packet(payload)
    if ether_type == 0x86DD:
        return parse_ipv6_packet(payload)
    if ether_type == 0x0806:
        return parse_arp_packet(payload)
    return None


def parse_ethernet_frame(value: Data | bytearray | memoryview) -> dict[str, Any]:
    """Decode Ethernet II/802.1Q and recursively decode network layers."""
    data = _bytes(value)
    _require(data, 14, "Ethernet frame")
    ether_type = int.from_bytes(data[12:14], "big")
    position = 14
    vlans: list[dict[str, Any]] = []
    while ether_type in {0x8100, 0x88A8}:
        _require(data[position:], 4, "VLAN tag")
        tag = int.from_bytes(data[position : position + 2], "big")
        vlans.append(
            {
                "tpid": ether_type,
                "priority": tag >> 13,
                "drop_eligible": bool(tag & 0x1000),
                "id": tag & 0xFFF,
            }
        )
        ether_type = int.from_bytes(data[position + 2 : position + 4], "big")
        position += 4
    payload = data[position:]
    result: dict[str, Any] = {
        "protocol": "Ethernet",
        "destination": _mac(data[:6]),
        "source": _mac(data[6:12]),
        "ether_type": ether_type,
        "ether_type_name": _ETHERTYPES.get(ether_type, "Unknown"),
        "vlans": vlans,
        "header_length": position,
        "payload": payload,
    }
    if network := _network(ether_type, payload):
        result["network"] = network
    return result


def parse_packet(value: Data | bytearray | memoryview, *, link_type: int = 1) -> dict[str, Any]:
    """Decode one captured packet for a common libpcap link-layer type."""
    data = _bytes(value)
    if link_type == 1:
        return parse_ethernet_frame(data)
    if link_type in {101, 228, 229}:
        version = (
            4 if link_type == 228 else 6 if link_type == 229 else (data[0] >> 4 if data else 0)
        )
        if version == 4:
            return parse_ipv4_packet(data)
        if version == 6:
            return parse_ipv6_packet(data)
        raise ValueError("raw packet is neither IPv4 nor IPv6")
    if link_type == 0:
        _require(data, 4, "loopback header")
        family_le = int.from_bytes(data[:4], "little")
        family_be = int.from_bytes(data[:4], "big")
        family = family_le if family_le in {2, 10, 24, 28, 30} else family_be
        network = parse_ipv4_packet(data[4:]) if family == 2 else parse_ipv6_packet(data[4:])
        return {"protocol": "Loopback", "family": family, "payload": data[4:], "network": network}
    if link_type == 113:
        _require(data, 16, "Linux cooked v1 header")
        packet_type, hardware_type, address_length = struct.unpack_from("!HHH", data)
        ether_type = int.from_bytes(data[14:16], "big")
        payload = data[16:]
        result = {
            "protocol": "Linux cooked v1",
            "packet_type": packet_type,
            "hardware_type": hardware_type,
            "address": data[6 : 6 + min(address_length, 8)],
            "ether_type": ether_type,
            "payload": payload,
        }
        if network := _network(ether_type, payload):
            result["network"] = network
        return result
    if link_type == 276:
        _require(data, 20, "Linux cooked v2 header")
        ether_type = int.from_bytes(data[:2], "big")
        payload = data[20:]
        result = {
            "protocol": "Linux cooked v2",
            "ether_type": ether_type,
            "interface_index": int.from_bytes(data[4:8], "big"),
            "hardware_type": int.from_bytes(data[8:10], "big"),
            "packet_type": data[10],
            "address": data[12 : 12 + min(data[11], 8)],
            "payload": payload,
        }
        if network := _network(ether_type, payload):
            result["network"] = network
        return result
    return {"protocol": "Unknown link type", "link_type": link_type, "payload": data}


def _capture_packet(
    data: bytes,
    *,
    link_type: int,
    index: int,
    captured_length: int,
    original_length: int,
    timestamp_ns: int | None,
) -> dict[str, Any]:
    packet: dict[str, Any] = {
        "index": index,
        "timestamp_ns": timestamp_ns,
        "captured_length": captured_length,
        "original_length": original_length,
        "data": data,
    }
    try:
        packet["decoded"] = parse_packet(data, link_type=link_type)
    except ValueError as exc:
        packet["decode_error"] = str(exc)
    return packet


def parse_pcap(
    value: Data | bytearray | memoryview,
    *,
    max_packets: int = 100_000,
    max_packet_size: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Decode a classic PCAP capture and every supported packet layer."""
    data = _bytes(value)
    _require(data, 24, "PCAP global header")
    variants = {
        b"\xa1\xb2\xc3\xd4": (">", "microseconds", 1_000),
        b"\xd4\xc3\xb2\xa1": ("<", "microseconds", 1_000),
        b"\xa1\xb2\x3c\x4d": (">", "nanoseconds", 1),
        b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds", 1),
    }
    try:
        endian, resolution, multiplier = variants[data[:4]]
    except KeyError as exc:
        raise ValueError("not a supported classic PCAP file") from exc
    major, minor, timezone, accuracy, snaplen, network = struct.unpack_from(
        f"{endian}HHiIII", data, 4
    )
    link_type = network & 0xFFFF
    packets: list[dict[str, Any]] = []
    position = 24
    while position < len(data):
        if len(packets) >= max_packets:
            raise ValueError(f"capture exceeds max_packets={max_packets}")
        _require(data[position:], 16, "PCAP packet header")
        seconds, fraction, captured_length, original_length = struct.unpack_from(
            f"{endian}IIII", data, position
        )
        position += 16
        maximum_fraction = 1_000_000 if resolution == "microseconds" else 1_000_000_000
        if fraction >= maximum_fraction:
            raise ValueError(f"invalid PCAP {resolution} timestamp fraction: {fraction}")
        if captured_length > max_packet_size:
            raise ValueError(f"captured packet exceeds max_packet_size={max_packet_size}")
        end = position + captured_length
        if end > len(data):
            raise ValueError("captured packet exceeds PCAP file length")
        packet_data = data[position:end]
        packets.append(
            _capture_packet(
                packet_data,
                link_type=link_type,
                index=len(packets),
                captured_length=captured_length,
                original_length=original_length,
                timestamp_ns=seconds * 1_000_000_000 + fraction * multiplier,
            )
        )
        position = end
    return {
        "format": "pcap",
        "byte_order": "little" if endian == "<" else "big",
        "timestamp_resolution": resolution,
        "version_major": major,
        "version_minor": minor,
        "timezone_correction": timezone,
        "timestamp_accuracy": accuracy,
        "snapshot_length": snaplen,
        "link_type": link_type,
        "link_type_name": _LINK_TYPES.get(link_type, "Unknown"),
        "packets": packets,
    }


def _pcapng_options(data: bytes, endian: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    position = 0
    while position + 4 <= len(data):
        code, length = struct.unpack_from(f"{endian}HH", data, position)
        position += 4
        if code == 0:
            break
        end = position + length
        if end > len(data):
            raise ValueError("PCAPNG option exceeds block")
        raw = data[position:end]
        option: dict[str, Any] = {"code": code, "value": raw}
        if code in {1, 2, 3, 4, 12}:
            option["text"] = raw.decode("utf-8", "replace")
        output.append(option)
        position = (end + 3) & ~3
    if any(data[position:]):
        raise ValueError("non-zero PCAPNG option padding")
    return output


def _interface_timing(options: Sequence[Mapping[str, Any]], endian: str) -> tuple[int, int, int]:
    numerator, denominator, offset_ns = 1_000_000_000, 1_000_000, 0
    for option in options:
        if option["code"] == 9 and len(option["value"]) == 1:
            raw = bytes(option["value"])[0]
            denominator = 2 ** (raw & 0x7F) if raw & 0x80 else 10**raw
        elif option["code"] == 14 and len(option["value"]) == 8:
            offset_ns = (
                int.from_bytes(
                    bytes(option["value"]),
                    "little" if endian == "<" else "big",
                    signed=True,
                )
                * 1_000_000_000
            )
    return numerator, denominator, offset_ns


def parse_pcapng(
    value: Data | bytearray | memoryview,
    *,
    max_packets: int = 100_000,
    max_packet_size: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Decode PCAPNG sections, interfaces, enhanced/simple packet blocks."""
    data = _bytes(value)
    _require(data, 28, "PCAPNG section header")
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("not a PCAPNG file")
    position = 0
    endian = "<"
    section_interfaces: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    while position < len(data):
        _require(data[position:], 12, "PCAPNG block")
        if data[position : position + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[position + 8 : position + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("invalid PCAPNG byte-order magic")
        block_type, block_length = struct.unpack_from(f"{endian}II", data, position)
        if block_length < 12 or block_length % 4 or position + block_length > len(data):
            raise ValueError("invalid PCAPNG block length")
        if struct.unpack_from(f"{endian}I", data, position + block_length - 4)[0] != block_length:
            raise ValueError("PCAPNG leading/trailing block lengths differ")
        body = data[position + 8 : position + block_length - 4]
        if block_type == 0x0A0D0D0A:
            _require(body, 16, "PCAPNG section body")
            major, minor = struct.unpack_from(f"{endian}HH", body, 4)
            section_length = struct.unpack_from(f"{endian}q", body, 8)[0]
            options = _pcapng_options(body[16:], endian)
            section_interfaces = []
            sections.append(
                {
                    "byte_order": "little" if endian == "<" else "big",
                    "version_major": major,
                    "version_minor": minor,
                    "section_length": section_length,
                    "options": options,
                }
            )
        elif block_type == 1:
            _require(body, 8, "PCAPNG interface description")
            link_type = struct.unpack_from(f"{endian}H", body)[0]
            snaplen = struct.unpack_from(f"{endian}I", body, 4)[0]
            options = _pcapng_options(body[8:], endian)
            numerator, denominator, offset_ns = _interface_timing(options, endian)
            interface = {
                "index": len(section_interfaces),
                "global_index": len(interfaces),
                "link_type": link_type,
                "link_type_name": _LINK_TYPES.get(link_type, "Unknown"),
                "snapshot_length": snaplen,
                "timestamp_numerator": numerator,
                "timestamp_denominator": denominator,
                "timestamp_offset_ns": offset_ns,
                "options": options,
            }
            section_interfaces.append(interface)
            interfaces.append(interface)
        elif block_type in {2, 6}:
            description = "PCAPNG packet" if block_type == 2 else "PCAPNG enhanced packet"
            _require(body, 20, description)
            if len(packets) >= max_packets:
                raise ValueError(f"capture exceeds max_packets={max_packets}")
            if block_type == 2:
                (
                    interface_id,
                    drops_count,
                    timestamp_high,
                    timestamp_low,
                    captured_length,
                    original_length,
                ) = struct.unpack_from(f"{endian}HHIIII", body)
            else:
                interface_id, timestamp_high, timestamp_low, captured_length, original_length = (
                    struct.unpack_from(f"{endian}IIIII", body)
                )
                drops_count = None
            if interface_id >= len(section_interfaces):
                raise ValueError("PCAPNG packet references an unknown interface")
            padded_end = 20 + ((captured_length + 3) & ~3)
            if captured_length > max_packet_size or padded_end > len(body):
                raise ValueError("invalid PCAPNG captured packet length")
            interface = section_interfaces[interface_id]
            timestamp = (timestamp_high << 32) | timestamp_low
            timestamp_ns = timestamp * int(interface["timestamp_numerator"]) // int(
                interface["timestamp_denominator"]
            ) + int(interface["timestamp_offset_ns"])
            packet_data = body[20 : 20 + captured_length]
            packet = _capture_packet(
                packet_data,
                link_type=int(interface["link_type"]),
                index=len(packets),
                captured_length=captured_length,
                original_length=original_length,
                timestamp_ns=timestamp_ns,
            )
            packet["options"] = _pcapng_options(body[padded_end:], endian)
            packet["interface_id"] = interface_id
            if drops_count is not None:
                packet["drops_count"] = drops_count
            packets.append(packet)
        elif block_type == 3:
            _require(body, 4, "PCAPNG simple packet")
            if not section_interfaces:
                raise ValueError("PCAPNG simple packet has no interface")
            if len(packets) >= max_packets:
                raise ValueError(f"capture exceeds max_packets={max_packets}")
            original_length = struct.unpack_from(f"{endian}I", body)[0]
            snaplen = int(section_interfaces[0]["snapshot_length"])
            captured_length = min(
                original_length,
                snaplen or original_length,
                len(body) - 4,
            )
            if captured_length > max_packet_size:
                raise ValueError(f"captured packet exceeds max_packet_size={max_packet_size}")
            packet_data = body[4 : 4 + captured_length]
            interface = section_interfaces[0]
            packets.append(
                _capture_packet(
                    packet_data,
                    link_type=int(interface["link_type"]),
                    index=len(packets),
                    captured_length=captured_length,
                    original_length=original_length,
                    timestamp_ns=None,
                )
            )
        position += block_length
    return {"format": "pcapng", "sections": sections, "interfaces": interfaces, "packets": packets}


def parse_capture(
    value: Data | bytearray | memoryview,
    *,
    max_packets: int = 100_000,
    max_packet_size: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Auto-detect and decode PCAP or PCAPNG bytes."""
    data = _bytes(value)
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return parse_pcapng(data, max_packets=max_packets, max_packet_size=max_packet_size)
    return parse_pcap(data, max_packets=max_packets, max_packet_size=max_packet_size)


def read_capture(
    path: str | os.PathLike[str],
    *,
    max_file_size: int = 512 * 1024 * 1024,
    max_packets: int = 100_000,
    max_packet_size: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Read and parse a capture file with an explicit file-size limit."""
    capture_path = Path(path)
    size = capture_path.stat().st_size
    if size > max_file_size:
        raise ValueError(f"capture exceeds max_file_size={max_file_size}")
    return parse_capture(
        capture_path.read_bytes(), max_packets=max_packets, max_packet_size=max_packet_size
    )


def json_safe(value: Any) -> Any:
    """Recursively convert packet bytes to hexadecimal JSON-friendly objects."""
    if isinstance(value, bytes):
        return {"hex": value.hex(), "length": len(value)}
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def packet_json(value: Any, *, indent: int | None = 2) -> str:
    """Serialize decoded packet/capture data without losing byte lengths."""
    return json.dumps(json_safe(value), indent=indent, separators=None if indent else (",", ":"))


__all__ = [
    "json_safe",
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
]
