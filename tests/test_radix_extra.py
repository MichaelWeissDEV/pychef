"""Official Base92 and Bech32 vectors."""

from __future__ import annotations

import json

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("source", "encoded"),
    [("", ""), ("AB", "8y2"), ("Hello!!", ";K_$aOTo&"), ("base-92", "DX2?V<Y(*")],
)
def test_base92_official_vectors(source: str, encoded: str) -> None:
    assert bake(source, ["To Base92"]) == encoded
    assert bake(encoded, ["From Base92"]) == source.encode()


def test_base92_official_decode_and_error() -> None:
    assert bake("G'_DW[B", ["From Base92"]) == b"ietf!"
    with pytest.raises(OperationError, match="not a base92 character"):
        bake("~", ["From Base92"])


@pytest.mark.parametrize(
    ("source", "args", "expected"),
    [
        ("", ["bc", "Bech32", "Raw bytes", "Generic", 0], "bc1gmk9yu"),
        ("A", ["bc", "Bech32", "Raw bytes", "Generic", 0], "bc1gyufle22"),
        ("Hello", ["bc", "Bech32", "Raw bytes", "Generic", 0], "bc1fpjkcmr0gzsgcg"),
        ("test", ["custom", "Bech32", "Raw bytes", "Generic", 0], "custom1w3jhxaq593qur"),
        ("Hello", ["bc", "Bech32m", "Raw bytes", "Generic", 0], "bc1fpjkcmr0a7qya2"),
    ],
)
def test_bech32_official_encode_vectors(source: str, args: list[object], expected: str) -> None:
    assert bake(source, [{"op": "To Bech32", "args": args}]) == expected


def test_bech32_official_decode_formats() -> None:
    encoded = "bc1fpjkcmr0gzsgcg"
    assert bake(encoded, [{"op": "From Bech32", "args": ["Auto-detect", "Raw"]}]) == b"Hello"
    assert bake(encoded.upper(), [{"op": "From Bech32", "args": ["Auto-detect", "Hex"]}]) == (
        "48656c6c6f"
    )
    assert bake(encoded, [{"op": "From Bech32", "args": ["Bech32", "HRP: Hex"]}]) == (
        "bc: 48656c6c6f"
    )
    rendered = bake(encoded, [{"op": "From Bech32", "args": ["Bech32", "JSON"]}])
    assert isinstance(rendered, str)
    assert json.loads(rendered) == {"hrp": "bc", "encoding": "Bech32", "data": "48656c6c6f"}


def test_bech32_segwit_round_trip_and_errors() -> None:
    program = "00" * 20
    args = ["bc", "Bech32", "Hex", "Bitcoin SegWit", 0]
    address = bake(program, [{"op": "To Bech32", "args": args}])
    decoded = bake(
        address, [{"op": "From Bech32", "args": ["Auto-detect", "Bitcoin scriptPubKey"]}]
    )
    assert decoded == "0014" + program
    with pytest.raises(OperationError, match="cannot be empty"):
        bake("x", [{"op": "To Bech32", "args": ["", "Bech32", "Raw bytes", "Generic", 0]}])
    with pytest.raises(OperationError, match="checksum"):
        bake("bc1fpjkcmr0gzsgca", [{"op": "From Bech32", "args": ["Auto-detect", "Raw"]}])
