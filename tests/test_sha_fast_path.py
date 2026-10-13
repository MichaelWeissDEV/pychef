"""Tests verifying bit-exact correctness of SHA-1 and SHA-2 fast paths."""

from __future__ import annotations

import hashlib

from pychef import bake
from pychef.operations.sha_custom import sha256 as _sha256
from pychef.operations.sha_custom import sha512 as _sha512


def test_sha1_fast_path_and_custom_rounds() -> None:
    data = "The quick brown fox jumps over the lazy dog"
    # Default 80 rounds
    res_fast = bake(data, ["SHA1"])
    assert res_fast == hashlib.sha1(data.encode()).hexdigest()

    # Custom rounds (e.g. 70) fallback
    res_custom = bake(data, [{"op": "SHA1", "args": [70]}])
    assert len(res_custom) == 40
    assert res_custom != res_fast


def test_sha2_sizes_fast_path_exactness() -> None:
    data = "CyberChef PyChef Parity Verification 2026"
    encoded = data.encode()

    # SHA-256 (64 rounds)
    assert bake(data, [{"op": "SHA2", "args": ["256", 64]}]) == hashlib.sha256(encoded).hexdigest()
    assert bake(data, [{"op": "SHA2", "args": ["256", 64]}]) == _sha256(encoded, 256, 64).hex()

    # SHA-224 (64 rounds)
    assert bake(data, [{"op": "SHA2", "args": ["224", 64]}]) == hashlib.sha224(encoded).hexdigest()
    assert bake(data, [{"op": "SHA2", "args": ["224", 64]}]) == _sha256(encoded, 224, 64).hex()

    # SHA-384 (160 rounds)
    assert (
        bake(data, [{"op": "SHA2", "args": ["384", 64, 160]}])
        == hashlib.sha384(encoded).hexdigest()
    )
    assert (
        bake(data, [{"op": "SHA2", "args": ["384", 64, 160]}]) == _sha512(encoded, 384, 160).hex()
    )

    # SHA-512 (160 rounds)
    assert (
        bake(data, [{"op": "SHA2", "args": ["512", 64, 160]}])
        == hashlib.sha512(encoded).hexdigest()
    )
    assert (
        bake(data, [{"op": "SHA2", "args": ["512", 64, 160]}]) == _sha512(encoded, 512, 160).hex()
    )


def test_sha2_custom_rounds_fallback() -> None:
    data = "custom rounds test"
    encoded = data.encode()

    # SHA-256 with 50 rounds
    res_custom_256 = bake(data, [{"op": "SHA2", "args": ["256", 50]}])
    assert res_custom_256 == _sha256(encoded, 256, 50).hex()

    # SHA-512 with 100 rounds
    res_custom_512 = bake(data, [{"op": "SHA2", "args": ["512", 64, 100]}])
    assert res_custom_512 == _sha512(encoded, 512, 100).hex()
