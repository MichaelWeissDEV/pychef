"""Tests for structured packet and capture-file decoding."""

from __future__ import annotations

import json
import struct
from collections.abc import Callable
from pathlib import Path

import pytest

from pychef import (
    Pipeline,
    json_safe,
    packet_json,
    parse_capture,
    parse_dns_message,
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_packet,
    parse_pcap,
    parse_pcapng,
    parse_tcp_segment,
    parse_udp_datagram,
    read_capture,
)


def _dns_query() -> bytes:
    return (
        bytes.fromhex("123401000001000000000000")
        + b"\x07example\x03com\0"
        + bytes.fromhex("00010001")
    )


def _udp_dns() -> bytes:
    payload = _dns_query()
    return struct.pack("!HHHH", 44444, 53, len(payload) + 8, 0) + payload


def _ipv4_udp() -> bytes:
    udp = _udp_dns()
    return (
        bytes.fromhex("4500")
        + struct.pack("!H", 20 + len(udp))
        + bytes.fromhex("0001400040110000c000020108080808")
        + udp
    )


def _ethernet() -> bytes:
    return bytes.fromhex("aabbccddeeff0011223344550800") + _ipv4_udp()


def _pcap() -> bytes:
    frame = _ethernet()
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1_700_000_000, 123456, len(frame), len(frame))
    return global_header + packet_header + frame


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def _pcapng() -> bytes:
    frame = _ethernet()
    section = _pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    padded = frame + b"\0" * (-len(frame) % 4)
    packet = _pcapng_block(
        6, struct.pack("<IIIII", 0, 0, 1_500_000, len(frame), len(frame)) + padded
    )
    return section + interface + packet


def test_dns_udp_ipv4_and_ethernet_are_recursively_decoded() -> None:
    dns = parse_dns_message(_dns_query())
    assert dns["id"] == 0x1234
    assert dns["questions"] == [{"name": "example.com", "type": 1, "class": 1}]

    udp = parse_udp_datagram(_udp_dns())
    assert udp["destination_port"] == 53
    assert udp["application"]["protocol"] == "DNS"

    ipv4 = parse_ipv4_packet(_ipv4_udp())
    assert ipv4["source"] == "192.0.2.1"
    assert ipv4["destination"] == "8.8.8.8"
    assert ipv4["transport"]["application"]["questions"][0]["name"] == "example.com"

    ethernet = parse_ethernet_frame(_ethernet())
    assert ethernet["source"] == "00:11:22:33:44:55"
    assert ethernet["network"]["transport"]["destination_port"] == 53
    assert parse_packet(_ethernet(), link_type=1) == ethernet
    assert Pipeline().parse_packet().select("network", "source")(_ethernet()) == "192.0.2.1"


def test_tcp_options_http_and_tls_records() -> None:
    http = b"GET /flag HTTP/1.1\r\nHost: ctf.example\r\n\r\n"
    options = bytes.fromhex("020405b401030307")
    tcp = struct.pack("!HHII", 31337, 80, 1, 0) + bytes([0x70, 0x02])
    tcp += struct.pack("!HHH", 8192, 0, 0) + options + http
    parsed = parse_tcp_segment(tcp)
    assert parsed["flags"]["SYN"] is True
    assert parsed["options"][0]["value"] == 1460
    assert parsed["application"]["protocol"] == "HTTP"
    assert parsed["application"]["headers"]["Host"] == "ctf.example"

    tls_payload = bytes.fromhex("160303000401000000")
    tls_tcp = struct.pack("!HHII", 443, 44444, 0, 0) + bytes([0x50, 0x18])
    tls_tcp += struct.pack("!HHH", 1024, 0, 0) + tls_payload
    assert parse_tcp_segment(tls_tcp)["application"]["handshake_type"] == 1


def test_classic_pcap_parse_auto_detect_pipeline_and_json(tmp_path: Path) -> None:
    capture = parse_pcap(_pcap())
    assert capture["format"] == "pcap"
    assert capture["byte_order"] == "little"
    assert capture["timestamp_resolution"] == "microseconds"
    assert capture["packets"][0]["timestamp_ns"] == 1_700_000_000_123_456_000
    decoded = capture["packets"][0]["decoded"]
    assert decoded["network"]["transport"]["application"]["id"] == 0x1234
    assert parse_capture(_pcap())["packets"][0]["data"] == _ethernet()

    pipeline = Pipeline().parse_capture().select("packets", 0, "decoded", "network", "source")
    assert pipeline(_pcap()) == "192.0.2.1"
    safe = json_safe(capture)
    assert safe["packets"][0]["data"] == {"hex": _ethernet().hex(), "length": len(_ethernet())}
    assert json.loads(packet_json(capture))["format"] == "pcap"

    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(_pcap())
    assert read_capture(capture_path)["packets"][0]["original_length"] == len(_ethernet())


def test_pcapng_section_interface_and_enhanced_packet() -> None:
    capture = parse_pcapng(_pcapng())
    assert capture["format"] == "pcapng"
    assert capture["sections"][0]["byte_order"] == "little"
    assert capture["interfaces"][0]["link_type_name"] == "Ethernet"
    assert capture["packets"][0]["timestamp_ns"] == 1_500_000_000
    assert capture["packets"][0]["decoded"]["network"]["destination"] == "8.8.8.8"
    assert parse_capture(_pcapng())["format"] == "pcapng"


@pytest.mark.parametrize(
    "parser,data,match",
    [
        (parse_ethernet_frame, b"short", "truncated Ethernet"),
        (parse_ipv4_packet, b"\x45" + b"\0" * 5, "truncated IPv4"),
        (parse_udp_datagram, b"\0" * 4, "truncated UDP"),
        (parse_tcp_segment, b"\0" * 10, "truncated TCP"),
        (parse_pcap, b"bad", "truncated PCAP"),
        (parse_pcapng, b"bad", "truncated PCAPNG"),
    ],
)
def test_packet_parsers_reject_truncated_inputs(
    parser: Callable[[bytes], object], data: bytes, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        parser(data)


def test_capture_limits_and_malformed_lengths_are_rejected() -> None:
    with pytest.raises(ValueError, match="max_packets"):
        parse_pcap(_pcap(), max_packets=0)
    malformed = bytearray(_pcap())
    malformed[32:36] = struct.pack("<I", 20_000_000)
    with pytest.raises(ValueError, match="max_packet_size"):
        parse_pcap(malformed)
    malformed_ng = bytearray(_pcapng())
    malformed_ng[4:8] = struct.pack("<I", 16)
    with pytest.raises(ValueError, match="length"):
        parse_pcapng(malformed_ng)
