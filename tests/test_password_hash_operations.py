from __future__ import annotations

import pytest

from pychef import bake
from pychef.errors import OperationError


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        ("Argon2i", "$argon2i$v=19$m=32,t=2,p=1$c29tZXNhbHQ$m+uya8+LhdfdIZvJdrKTOg"),
        ("Argon2d", "$argon2d$v=19$m=32,t=2,p=1$c29tZXNhbHQ$xjQbXQXwIatho/e1sFZLaQ"),
        ("Argon2id", "$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$TAxiBekO4iOHvYc3q/zn/A"),
    ],
)
def test_argon2_matches_reference_vectors(variant: str, expected: str) -> None:
    args = [{"option": "UTF8", "string": "somesalt"}, 2, 32, 1, 16, variant, "Encoded hash"]
    assert bake("password", [{"op": "Argon2", "args": args}]) == expected
    assert bake("password", [{"op": "Argon2 compare", "args": [expected]}]) == "Match: password"
    assert bake("wrong", [{"op": "Argon2 compare", "args": [expected]}]) == "No match"


def test_argon2_hex_and_raw_formats() -> None:
    base = [{"option": "Hex", "string": "736f6d6573616c74"}, 1, 32, 1, 8, "Argon2id"]
    raw = bake(b"password", [{"op": "Argon2", "args": [*base, "Raw hash"]}])
    assert isinstance(raw, bytes) and len(raw) == 8
    assert bake(b"password", [{"op": "Argon2", "args": [*base, "Hex hash"]}]) == raw.hex()


def test_bcrypt_matches_reference_vector_and_compare() -> None:
    reference = "$2b$04$hDZ7E7pBZtbvTy8KXtYcdu7sZdKzMpNpk0w83PWK/yeo681Qthwc."
    assert bake("password", [{"op": "Bcrypt compare", "args": [reference]}]) == "Match: password"
    assert bake("not it", [{"op": "Bcrypt compare", "args": [reference]}]) == "No match"


def test_bcrypt_generates_a_valid_modular_hash() -> None:
    result = bake("swordfish", [{"op": "Bcrypt", "args": [4]}])
    assert isinstance(result, str) and result.startswith("$2b$04$") and len(result) == 60
    assert bake("swordfish", [{"op": "Bcrypt compare", "args": [result]}]) == "Match: swordfish"


def test_password_hash_validation() -> None:
    with pytest.raises(OperationError, match="salt must be at least"):
        bake("x", [{"op": "Argon2", "args": [{"option": "UTF8", "string": "short"}, 1, 8, 1, 8]}])
    with pytest.raises(OperationError, match="invalid hash"):
        bake("x", [{"op": "Bcrypt compare", "args": ["invalid"]}])
