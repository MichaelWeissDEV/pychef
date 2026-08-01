"""Tests for KDF, fuzzy hashing, legacy hashes, and block ciphers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from pychef import registry


def run(name: str, value: str | bytes, args: Sequence[Any] | None = None) -> Any:
    return registry.get(name).run(value, args or [])


def toggle(value: bytes, option: str = "Hex") -> dict[str, str]:
    if option == "Hex":
        string = value.hex()
    elif option == "Base64":
        import base64

        string = base64.b64encode(value).decode()
    else:
        string = value.decode("latin-1" if option == "Latin1" else "utf-8")
    return {"option": option, "string": string}


def test_scrypt_known_vector_and_encodings() -> None:
    assert run("Scrypt", "password", [toggle(b"salt", "UTF8"), 16, 1, 1, 16]) == (
        "45133c3dfba48c82235df51a53499241"
    )
    assert len(run("Scrypt", "p", [toggle(b"s", "Base64"), 16, 1, 1, 8])) == 16
    with pytest.raises(ValueError):
        run("Scrypt", "p", [toggle(b"s"), 15, 1, 1, 8])
    with pytest.raises(ValueError):
        run("Scrypt", "p", [toggle(b"s"), 16, 0, 1, 8])


def test_fuzzy_hashes_and_comparison() -> None:
    left = run("CTPH", "the quick brown fox jumps over the lazy dog" * 4)
    right = run("SSDEEP", "the quick brown fox jumps over the lazy dog" * 4)
    different = run("CTPH", "completely different payload" * 6)
    assert left == right and left.count(":") == 2
    assert run("Compare CTPH hashes", f"{left}\n{right}") == "100"
    score = int(run("Compare SSDEEP hashes", f"{left},{different}", ["Comma"]))
    assert 0 <= score <= 100
    with pytest.raises(ValueError):
        run("Compare CTPH hashes", "one hash only")
    with pytest.raises(ValueError):
        run("Compare CTPH hashes", "bad\nalso-bad")


@pytest.mark.parametrize(
    ("name", "args", "length"),
    [
        ("MD6", [128, 10, "key"], 32),
        ("MD6", [512, 64, ""], 128),
        ("Snefru", [128, 2], 32),
        ("Snefru", [256, 16], 64),
        ("Streebog", ["256"], 64),
        ("Streebog", ["512"], 128),
        ("Whirlpool", ["Whirlpool"], 128),
        ("Whirlpool", ["Whirlpool-T"], 128),
        ("Whirlpool", ["Whirlpool-0"], 128),
        ("GOST Hash", ["GOST 28147 (1994)", "256", "D-A"], 64),
        ("GOST Hash", ["GOST R 34.11 (Streebog, 2012)", "512"], 128),
    ],
)
def test_legacy_digest_shapes(name: str, args: list[object], length: int) -> None:
    digest = run(name, "abc", args)
    assert isinstance(digest, str) and len(digest) == length
    int(digest, 16)


def test_legacy_digest_validation() -> None:
    for name, args in (
        ("MD6", [0, 64, ""]),
        ("MD6", [256, -1, ""]),
        ("Snefru", [192, 8]),
        ("Streebog", [128]),
        ("Whirlpool", ["unknown"]),
        ("GOST Hash", ["GOST", 128]),
    ):
        with pytest.raises(ValueError):
            run(name, "abc", args)


def test_generate_all_hashes_and_checksums() -> None:
    hashes = run("Generate all hashes", "abc")
    assert "MD5: 900150983cd24fb0d6963f7d28e17f72" in hashes
    assert "SHA-256: ba7816bf" in hashes
    assert "SSDEEP:" in hashes
    checksums = run("Generate all checksums", "abc")
    assert "CRC-32: 352441c2" in checksums
    assert all(name in checksums for name in ("Adler-32", "Fletcher-8", "Fletcher-64"))


def gost_args(mode: str, padding: str = "PKCS5") -> list[object]:
    return [
        toggle(bytes(range(32))),
        toggle(b"12345678"),
        "Raw",
        "Raw",
        "GOST R 34.12 (Magma, 2015)",
        "E-Z",
        mode,
        "NO",
        padding,
    ]


@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR", "OFB", "CFB"])
def test_gost_encrypt_decrypt_modes(mode: str) -> None:
    args = gost_args(mode)
    encrypted = run("GOST Encrypt", "GOST round trip", args)
    assert encrypted != b"GOST round trip"
    assert run("GOST Decrypt", encrypted, args) == b"GOST round trip"


def test_gost_hex_zero_and_bit_padding() -> None:
    for padding in ("NO", "ZERO", "BIT"):
        message = b"12345678" if padding == "NO" else b"short"
        args = gost_args("ECB", padding)
        args[2] = "Hex"
        args[3] = "Hex"
        encrypted = run("GOST Encrypt", message.hex(), args)
        decrypted = run("GOST Decrypt", encrypted, args)
        assert bytes.fromhex(decrypted).startswith(message)
    with pytest.raises(ValueError):
        run("GOST Encrypt", "x", [toggle(b"short")])


def test_gost_sign_verify_and_key_wrap() -> None:
    key = toggle(bytes(range(32)))
    signature = run("GOST Sign", "message", [key])
    assert run("GOST Verify", "message", [key, signature]) == "Verified OK"
    assert run("GOST Verify", "changed", [key, signature]) == "Verification Failure"
    wrapped = run("GOST Key Wrap", b"secret key material", [key])
    assert run("GOST Key Unwrap", wrapped, [key]) == b"secret key material"
    corrupted = wrapped[:-2] + ("00" if wrapped[-2:] != "00" else "ff")
    with pytest.raises(ValueError):
        run("GOST Key Unwrap", corrupted, [key])


@pytest.mark.parametrize("mode", ["CBC", "ECB"])
def test_twofish_round_trip(mode: str) -> None:
    args = [toggle(bytes(range(16))), toggle(bytes(range(16, 32))), mode, "PKCS7"]
    encrypted = run("Twofish Encrypt", "twofish round trip", args)
    assert run("Twofish Decrypt", encrypted, args) == b"twofish round trip"


def test_twofish_no_padding_and_validation() -> None:
    args = [toggle(bytes(range(24))), toggle(bytes(16)), "ECB", "NoPadding"]
    data = bytes(range(16))
    encrypted = run("Twofish Encrypt", data, args)
    assert run("Twofish Decrypt", encrypted, args) == data
    with pytest.raises(ValueError):
        run("Twofish Encrypt", data, [toggle(b"bad"), toggle(bytes(16)), "ECB", "NoPadding"])
