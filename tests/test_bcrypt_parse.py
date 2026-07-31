"""Structured bcrypt hash parsing tests."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


def test_bcrypt_parse_fields() -> None:
    value = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    assert bake(value, [{"op": "Bcrypt parse", "args": []}]) == (
        "Rounds: 10\n"
        "Salt: $2a$10$N9qo8uLOickgx2ZMRZoMye\n"
        "Password hash: IjZAgcfl7p92ldGxad68LJZdL17lhWy\n"
        f"Full hash: {value}"
    )


@pytest.mark.parametrize("value", ["", "$2a$03$" + "a" * 53, "$2a$10$invalid"])
def test_bcrypt_parse_rejects_invalid_hashes(value: str) -> None:
    with pytest.raises(OperationError, match="invalid hash"):
        bake(value, [{"op": "Bcrypt parse", "args": []}])
