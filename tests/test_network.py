"""Networking operation compatibility tests."""

from __future__ import annotations

from pychef import bake


def test_defang_and_fang() -> None:
    source = "http://example.com/1.2.3.4"
    defanged = bake(source, ["Defang URL"])
    assert defanged == "hxxp[://]example[.]com/1[.]2[.]3[.]4"
    assert bake(defanged, ["Fang URL"]) == source
    assert bake("1.2.3.4", ["Defang IP Addresses"]) == "1[.]2[.]3[.]4"


def test_extract_indicators() -> None:
    text = "mail a@example.com URL https://example.com/a IP 8.8.8.8 MAC aa:bb:cc:dd:ee:ff"
    assert bake(text, ["Extract email addresses"]) == "a@example.com"
    assert bake(text, ["Extract URLs"]) == "https://example.com/a"
    assert bake(text, ["Extract domains"]).splitlines() == ["example.com", "example.com"]
    assert bake(text, ["Extract MAC addresses"]) == "aa:bb:cc:dd:ee:ff"
    assert bake(text, ["Extract IP addresses"]) == "8.8.8.8"


def test_change_ip_format_official_vectors() -> None:
    vectors = [
        ("192.168.1.1", ["Dotted Decimal", "Hex"], "c0a80101"),
        ("3232235777", ["Decimal", "Dotted Decimal"], "192.168.1.1"),
        ("c0a80101", ["Hex", "Octal"], "030052000401"),
        ("030052000401", ["Octal", "Decimal"], "3232235777"),
    ]
    for source, args, expected in vectors:
        assert bake(source, [{"op": "Change IP format", "args": args}]) == expected


def test_mac_format_ipv6_and_grouping() -> None:
    formatted = bake(
        "aabbccddeeff", [{"op": "Format MAC addresses", "args": ["Lower only", False, False, True]}]
    )
    assert formatted == "aa:bb:cc:dd:ee:ff"
    parsed = bake("::1", ["Parse IPv6 address"])
    assert isinstance(parsed, str)
    assert parsed.startswith("Longhand:  0000:0000:0000:0000:0000:0000:0000:0001")
    grouped = bake(
        "10.0.0.1\n10.0.0.2\n10.0.1.1",
        [{"op": "Group IP addresses", "args": ["Line feed", 24, True]}],
    )
    assert grouped == "10.0.0.0/24\n10.0.1.0/24"


def test_parse_ip_range_official_ipv4_vector() -> None:
    expected = (
        "Network: 10.0.0.0\nCIDR: 30\nMask: 255.255.255.252\n"
        "Range: 10.0.0.0 - 10.0.0.3\nTotal addresses in range: 4\n\n"
        "10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3"
    )
    assert bake("10.0.0.0/30", [{"op": "Parse IP range", "args": [True, True, False]}]) == expected


def test_parse_uri() -> None:
    parsed = bake("https://user:pass@example.com:8443/a?x=1&x=2#top", ["Parse URI"])
    assert isinstance(parsed, str)
    assert "Protocol:\thttps:" in parsed
    assert "Auth:\t\tuser:pass" in parsed
    assert "Hostname:\texample.com" in parsed
    assert "x = 1,2" in parsed
