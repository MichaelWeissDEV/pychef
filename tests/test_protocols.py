"""Protocol operation vectors ported from CyberChef."""

from __future__ import annotations

import json

import pytest

from pychef import OperationError, bake


def test_official_udp_vectors() -> None:
    assert bake("04 89 00 35 00 2c 01 01", [{"op": "Parse UDP", "args": ["Hex"]}]) == (
        '{"Source port":1161,"Destination port":53,"Length":44,"Checksum":"0x0101"}'
    )
    assert bake("04 89 00 35 00 2c 01 01 02 02", [{"op": "Parse UDP", "args": ["Hex"]}]) == (
        '{"Source port":1161,"Destination port":53,"Length":44,"Checksum":"0x0101","Data":"0x0202"}'
    )
    with pytest.raises(OperationError, match="Need 8 bytes"):
        bake("04 89 00", [{"op": "Parse UDP", "args": ["Hex"]}])


def test_official_tcp_basic_vector() -> None:
    packet = json.loads(
        bake("c2eb0050a138132e70dc9fb9501804025ea70000", [{"op": "Parse TCP", "args": ["Hex"]}])
    )
    assert packet["Source port"] == 49899
    assert packet["Destination port"] == 80
    assert packet["Window size"] == "1026 (Scaled: 1026)"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "000000000000ffffffffffff08004500",
            "Source MAC: ff:ff:ff:ff:ff:ff\nDestination MAC: 00:00:00:00:00:00\nData:\n45 00",
        ),
        (
            "01000ccdcdd00013c3dfae188100a0760165aaaa",
            "Source MAC: 00:13:c3:df:ae:18\nDestination MAC: 01:00:0c:cd:cd:d0\n"
            "VLAN: 118\nData:\naa aa",
        ),
    ],
)
def test_official_ethernet_vectors(source: str, expected: str) -> None:
    assert (
        bake(source, [{"op": "Parse Ethernet frame", "args": ["Hex", "Text output"]}]) == expected
    )


def test_ethernet_packet_data_is_html_escaped() -> None:
    source = "000000000000ffffffffffff08003c696d67207372633d78206f6e6572726f723d78203e"
    assert bake(source, [{"op": "Parse Ethernet frame", "args": ["Hex", "Packet data"]}]) == (
        "&lt;img src=x onerror=x &gt;"
    )


def test_tlv_official_vectors_and_ber_long_form() -> None:
    source = b"\x05House\x04room\x04door"
    parsed = json.loads(bake(source, [{"op": "Parse TLV", "args": [0, 1, False]}]))
    assert parsed == [
        {"length": 5, "value": [72, 111, 117, 115, 101]},
        {"length": 4, "value": [114, 111, 111, 109]},
        {"length": 4, "value": [100, 111, 111, 114]},
    ]
    source = b"\x01\x81\x80" + b"B" * 128
    parsed = json.loads(bake(source, [{"op": "Parse TLV", "args": [1, 1, True]}]))
    assert parsed == [{"key": [1], "length": 128, "value": [66] * 128}]


def test_permissions_colour_oid_and_pem_round_trips() -> None:
    assert bake("755", ["Parse UNIX file permissions"]) == "Octal: 755\nSymbolic: rwxr-xr-x"
    colour = bake("#33669980", ["Parse colour code"])
    assert colour == "Hex: #33669980\nRGBA: rgba(51, 102, 153, 0.501961)"
    oid = "1.2.840.113549.1.1.11"
    encoded = bake(oid, ["Object Identifier to Hex"])
    assert bake(encoded, ["Hex to Object Identifier"]) == oid
    pem = bake("48656c6c6f", [{"op": "Hex to PEM", "args": ["DATA"]}])
    assert bake(pem, ["PEM to Hex"]) == "48656c6c6f"


def test_strip_packet_headers_and_ipv4_parser() -> None:
    ipv4 = bytes.fromhex("450000180000000040110000c0000201c6336402") + b"data"
    assert bake(ipv4, ["Strip IPv4 header"]) == b"data"
    parsed = bake(ipv4.hex(), [{"op": "Parse IPv4 header", "args": ["Hex", "Text output"]}])
    assert isinstance(parsed, str)
    assert "Source: 192.0.2.1" in parsed
    udp = bytes.fromhex("00010002000c0000") + b"data"
    assert bake(udp, ["Strip UDP header"]) == b"data"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("16030300", "[]"),
        (
            "140303000101",
            '[{"type":"change_cipher_spec","version":"0x0303","length":1,"value":"0x01"}]',
        ),
        (
            "1403030001",
            '[{"type":"change_cipher_spec","version":"0x0303","length":1,"truncated":true}]',
        ),
        (
            "150303001411770b5b5d1107853582",
            '[{"type":"alert","version":"0x0303","length":20,"truncated":true,'
            '"value":"0x11770b5b5d1107853582"}]',
        ),
        (
            "1603030032010000",
            '[{"type":"handshake","version":"0x0303","length":50,"truncated":true,'
            '"handshakeType":"client_hello"}]',
        ),
        (
            "160303000400000000",
            '[{"type":"handshake","version":"0x0303","length":4,"handshakeType":"hello_request"}]',
        ),
    ],
)
def test_parse_tls_record_official_basic_vectors(source: str, expected: str) -> None:
    assert bake(bytes.fromhex(source), ["Parse TLS record"]) == expected


def test_parse_tls_record_official_client_hello() -> None:
    source = (
        "16030300320100002e030345cd3a31beaebd2934dd4ec2a151d7a054eab8bc0e4e"
        "5b9d4b9abdaacd051076000004123443210200010000"
    )
    result = json.loads(bake(bytes.fromhex(source), ["Parse TLS record"]))[0]
    assert result["clientVersion"] == "0x0303"
    assert result["random"] == (
        "0x45cd3a31beaebd2934dd4ec2a151d7a054eab8bc0e4e5b9d4b9abdaacd051076"
    )
    assert result["cipherSuites"] == {"length": 4, "values": ["0x1234", "0x4321"]}
    assert result["compressionMethods"] == {"length": 2, "values": ["0x00", "0x01"]}
    assert result["extensions"] == {}
