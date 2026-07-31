"""Official CyberChef Keccak vectors."""

from __future__ import annotations

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("bits", "expected"),
    [
        (224, "4eaaf0e7a1e400efba71130722e1cb4d59b32afb400e654afec4f8ce"),
        (256, "acaf3289d7b601cbd114fb36c4d29c85bbfd5e133f14cb355c3fd8d99367964f"),
        (
            384,
            "4d60892fde7f967bcabdc47c73122ae6311fa1f9be90d721da32030f7467a2e3"
            "db3f9ccb3c746483f9d2b876e39def17",
        ),
        (
            512,
            "eda765576c84c600ed7f5d97510e92703b61f5215def2a161037fd9dd1f5b6ed4"
            "f86ce46073c0e3f34b52de0289e9c618798fff9dd4b1bfe035bdb8645fc6e37",
        ),
    ],
)
def test_keccak_official_vectors(bits: int, expected: str) -> None:
    assert bake("Hello, World!", [{"op": "Keccak", "args": [str(bits)]}]) == expected
