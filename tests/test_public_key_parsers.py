"""Official CyberChef ASN.1 and SSH host-key vectors."""

from __future__ import annotations

from pychef import bake


def test_parse_asn1_hex_official_vector() -> None:
    assert bake(b"Mouth-watering".hex(), ["Parse ASN.1 hex string"]) == (
        "UNKNOWN(77) 7574682d7761746572696e67\n"
    )


def test_parse_ssh_ed25519_official_vector() -> None:
    source = "AAAAC3NzaC1lZDI1NTE5AAAAIBOF6r99IkvqGu1kwZrHHIqjpTB5w79bpv67B/Aw3+WJ"
    assert bake(source, [{"op": "Parse SSH Host Key", "args": ["Base64"]}]) == (
        "Key type: ssh-ed25519\n"
        "x: 0x1385eabf7d224bea1aed64c19ac71c8aa3a53079c3bf5ba6febb07f030dfe589"
    )


def test_parse_ssh_ecdsa_official_vector_and_auto_extract() -> None:
    source = (
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGxZWSAGJyJQoVBw"
        "FCpr420eRUZDE/kw2YWm5vDro8050DZ1ZzqIuYaNl0BGzMcRTeasGtJuI8G84ZQQSgca3C4="
    )
    expected = (
        "Key type: ecdsa-sha2-nistp256\nCurve: nistp256\n"
        "Point: 0x046c59592006272250a15070142a6be36d1e45464313f930d985a6e6f0eba3cd39"
        "d03675673a88b9868d974046ccc7114de6ac1ad26e23c1bce194104a071adc2e"
    )
    assert bake(source, [{"op": "Parse SSH Host Key", "args": ["Base64"]}]) == expected
    public_line = f"ecdsa-sha2-nistp256 {source} test@example"
    assert bake(public_line, [{"op": "Parse SSH Host Key", "args": ["Auto"]}]) == expected
