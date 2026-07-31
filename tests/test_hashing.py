"""Official CyberChef hash vectors and checksum tests."""

from __future__ import annotations

import base64

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("operation", "args", "expected"),
    [
        ("MD5", [], "65a8e27d8879283831b664bd8b7f0ad4"),
        ("SHA1", [], "0a0a9f2a6772942557ab5355d76af442f8f65e01"),
        ("SHA2", ["224"], "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff"),
        ("SHA2", ["256"], "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"),
        (
            "SHA2",
            ["384"],
            "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515",
        ),
        (
            "SHA2",
            ["512"],
            "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387",
        ),
        ("SHA2", ["512/224"], "766745f058e8a0438f19de48ae56ea5f123fe738af39bca050a7547a"),
        ("SHA2", ["512/256"], "0686f0a605973dc1bf035d1e2b9bad1985a0bff712ddd88abd8d2593e5f99030"),
        ("SHA3", ["256"], "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef"),
    ],
)
def test_official_hash_vectors(operation: str, args: list[str], expected: str) -> None:
    assert bake("Hello, World!", [{"op": operation, "args": args}]) == expected


def test_blake2_official_vectors_and_encodings() -> None:
    expected = (
        "4386a08a265111c9896f56456e2cb61a64239115c4784cf438e36cc851221972da3fb011"
        "5f73cd02486254001f878ab1fd126aac69844ef1c1ca152379d0a9bd"
    )
    args = ["512", "Hex", {"string": "", "option": "UTF8"}]
    assert bake("Hello World", [{"op": "BLAKE2b", "args": args}]) == expected
    raw = bake("Hello World", [{"op": "BLAKE2s", "args": ["256", "Raw", ""]}])
    encoded = bake("Hello World", [{"op": "BLAKE2s", "args": ["256", "Base64", ""]}])
    assert base64.b64decode(encoded) == raw


def test_hmac_shake_and_checksums() -> None:
    assert (
        bake("data", [{"op": "HMAC", "args": [{"string": "key", "option": "UTF8"}, "SHA256"]}])
        == "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"
    )
    assert len(bake("data", [{"op": "Shake", "args": ["128", 128]}])) == 32
    assert bake("Wikipedia", ["Adler-32 Checksum"]) == "11e60398"
    assert bake(b"abc", [{"op": "XOR Checksum", "args": [2]}]) == "0262"


@pytest.mark.parametrize(
    ("plain", "seed", "signed", "expected"),
    [
        ("", 0, False, "0"),
        ("1", 0, False, "2484513939"),
        ("Hello World!", 0, False, "3691591037"),
        ("Hello World!", 1337, False, "1148600031"),
        ("foo", 0, False, "4138058784"),
        ("foo", 0, True, "-156908512"),
    ],
)
def test_murmurhash3_official_vectors(plain: str, seed: int, signed: bool, expected: str) -> None:
    assert bake(plain, [{"op": "MurmurHash3", "args": [seed, signed]}]) == expected


def test_analysis_operations() -> None:
    assert bake("aaaa", ["Entropy"]) == "-0.0"
    assert (
        bake(
            "karolin\nkathrin", [{"op": "Hamming Distance", "args": ["\\n", "Byte", "Raw string"]}]
        )
        == "3"
    )
    assert bake("ABAB", ["Index of Coincidence"]) == str(1 / 3)
    assert float(bake(bytes(range(256)), ["Chi Square"])) == 0
