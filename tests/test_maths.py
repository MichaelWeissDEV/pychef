"""Bitwise and arithmetic operation tests."""

from __future__ import annotations

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("operation", "args", "expected"),
    [
        ("Bit shift left", [1], "10101010 01010100 11111110 00000000"),
        ("Bit shift right", [1, "Logical shift"], "00101010 01010101 01111111 00000000"),
        ("Bit shift right", [1, "Arithmetic shift"], "00101010 11010101 11111111 00000000"),
    ],
)
def test_official_bit_shift_vectors(operation: str, args: list[object], expected: str) -> None:
    source = "01010101 10101010 11111111 00000000"
    result = bake(source, ["From Binary", {"op": operation, "args": args}, "To Binary"])
    assert result == expected


def test_bitwise_key_operations_and_not() -> None:
    key = {"string": "0f", "option": "Hex"}
    assert bake(b"\xf0\xaa", [{"op": "XOR", "args": [key]}]) == b"\xff\xa5"
    assert bake(b"\xf0\xaa", [{"op": "AND", "args": [key]}]) == b"\x00\x0a"
    assert bake(b"\xf0\xaa", [{"op": "OR", "args": [key]}]) == b"\xff\xaf"
    assert bake(b"\xff\x00", [{"op": "ADD", "args": [key]}]) == b"\x0e\x0f"
    assert bake(b"\x00\x0f", [{"op": "SUB", "args": [key]}]) == b"\xf1\x00"
    assert bake(b"\x00\xff", ["NOT"]) == b"\xff\x00"


@pytest.mark.parametrize(
    ("operation", "args", "expected"),
    [
        ("Rotate left", [1, False], "c2 c4 c6 62 64 66"),
        ("Rotate left", [2, True], "85 89 8c c4 c8 cd"),
        ("Rotate right", [1, False], "b0 31 b1 98 19 99"),
        ("Rotate right", [2, True], "d8 58 98 cc 4c 8c"),
    ],
)
def test_official_rotate_vectors(operation: str, args: list[object], expected: str) -> None:
    result = bake("61 62 63 31 32 33", ["From Hex", {"op": operation, "args": args}, "To Hex"])
    assert result == expected


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("Sum", "10"),
        ("Subtract", "-8"),
        ("Multiply", "24"),
        (
            "Divide",
            "0.04166666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666668",
        ),
        ("Mean", "2.5"),
        ("Median", "2.5"),
    ],
)
def test_arithmetic(operation: str, expected: str) -> None:
    assert bake("1 2 3 4", [{"op": operation, "args": ["Space"]}]) == expected


def test_mod_standard_deviation_and_number_theory() -> None:
    assert bake("3 4 5", [{"op": "MOD", "args": [2, "Space"]}]) == "1 0 1"
    assert bake("2 2 2", [{"op": "Standard Deviation", "args": ["Space"]}]) == "0"
    assert bake("", [{"op": "Modular Exponentiation", "args": ["4", "497", "13"]}]) == "445"
    assert bake("", [{"op": "Modular Inverse", "args": ["3", "11"]}]) == "4"
    gcd = bake("", [{"op": "Extended GCD", "args": ["240", "46"]}])
    assert isinstance(gcd, str)
    assert gcd.startswith("gcd: 2\n")
    assert (
        bake("test", [{"op": "Text-Integer Conversion", "args": ["Hexadecimal"]}]) == "0x74657374"
    )
    assert bake("0x74657374", [{"op": "Text-Integer Conversion", "args": ["String"]}]) == "test"


def test_distances_and_ror13() -> None:
    assert (
        bake("kitten\nsitting", [{"op": "Levenshtein Distance", "args": ["\\n", 1, 1, 1]}]) == "3"
    )
    assert float(bake("0,0,0,1", ["Haversine distance"])) == pytest.approx(111194.9266, rel=1e-6)
    result = bake("kernel32.dll", ["ROR13"])
    assert isinstance(result, str)
    assert result.startswith("0x")
