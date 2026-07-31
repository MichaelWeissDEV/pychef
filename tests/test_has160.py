"""Official CyberChef and published HAS-160 vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("", "307964ef34151d37c8047adec7ab50f4ff89762d"),
        ("a", "4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8"),
        ("abc", "975e810488cf2a3d49838478124afce4b1c78804"),
        ("message digest", "2338dbc8638d31225f73086246ba529f96710bc6"),
        ("Hello, World!", "8f6dd8d7c8a04b1cb3831adc358b1e4ac2ed5984"),
        ("test", "cb15e491eec6e769771d1f811315139c93071084"),
    ],
)
def test_has160_vectors(message: str, expected: str) -> None:
    assert bake(message, ["HAS-160"]) == expected


def test_has160_configurable_rounds_and_validation() -> None:
    partial = bake("abc", [{"op": "HAS-160", "args": [20]}])
    assert isinstance(partial, str) and len(partial) == 40
    with pytest.raises(OperationError, match="between 1 and 80"):
        bake("abc", [{"op": "HAS-160", "args": [81]}])
