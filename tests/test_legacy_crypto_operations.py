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
    left = run("CTPH", "If You Can't Stand the Heat, Get Out of the Kitchen")
    right = run("SSDEEP", "shotgun tyranny snugly")
    assert left == "A:+EgFgBKAA0V0UFfClEs6:+Qk0gUFse"
    assert right == "3:DLIXzMQCJc:XERKc"
    assert run("Compare CTPH hashes", f"{left}\n{left}") == "100"
    assert run("Compare SSDEEP hashes", f"{right}\n{right}") == "100"
    different = run("SSDEEP", "completely different payload" * 6)
    score = float(run("Compare SSDEEP hashes", f"{right},{different}", ["Comma"]))
    assert 0 <= score <= 100
    assert run("Compare CTPH hashes", "1234\n3456") == "0"
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
        ("Snefru", [256, 8], 64),
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
        ("MD6", [-1, 64, ""]),
        ("MD6", [256, -1, ""]),
        ("Snefru", [190, 8]),
        ("Streebog", [128]),
        ("Whirlpool", ["unknown"]),
        ("GOST Hash", ["GOST", 128]),
    ):
        with pytest.raises(ValueError):
            run(name, "abc", args)


@pytest.mark.parametrize(
    ("message", "bits", "expected"),
    [
        ("", "256", "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"),
        (
            "",
            "512",
            "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7"
            "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "256",
            "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "512",
            "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b9"
            "7e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe",
        ),
    ],
)
def test_streebog_official_vectors(message: str, bits: str, expected: str) -> None:
    assert run("Streebog", message, [bits]) == expected
    assert run("GOST Hash", message, ["GOST R 34.11 (Streebog, 2012)", bits]) == expected


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        (
            "Whirlpool",
            "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1"
            "ec44076ce7a8f7bfa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b",
        ),
        (
            "Whirlpool-T",
            "16c581089b6a6f356ae56e16a63a4c613eecd82a2a894b293f5ee45c37a31d09d"
            "7a8b60bfa7e414bd4a7166662cea882b5cf8c96b7d583fc610ad202591bcdb1",
        ),
        (
            "Whirlpool-0",
            "1c327026f565a0105a827efbfb3d3635cdb042c0aabb8416e96deb128e6c5c8684"
            "b13541cf31c26c1488949df050311c6999a12eb0e7002ad716350f5c7700ca",
        ),
    ],
)
def test_whirlpool_family_official_vectors(variant: str, expected: str) -> None:
    assert run("Whirlpool", "Hello, World!", [variant, 10]) == expected


def test_whirlpool_round_validation() -> None:
    assert run("Whirlpool", "abc", ["Whirlpool", 10]).startswith("4e2448a4c6f486bb")
    with pytest.raises(ValueError, match="rounds"):
        run("Whirlpool", "abc", ["Whirlpool", 0])


@pytest.mark.parametrize(
    ("bits", "rounds", "expected"),
    [
        (128, 2, "a4ad2b8848580511d0884fb4233a7e7a"),
        (128, 4, "d154eae2c9ffbcd2e1bdaf0b84736126"),
        (128, 8, "6f3d55b69557abb0a3c4e9de9d29ba5d"),
        (256, 2, "65736daba648de28ef4c4a316b4684584ecf9f22ddb5c457729e6bf0f40113c4"),
        (256, 4, "71b0ea4b3e33f2e58bcc67c8a8de060b99ec0107355bbfdc18d8f65f0194ffcc"),
        (256, 8, "255cd401414c79588cf689e8d5ff0536a2cfab83fcae36e654f202b09bc4b8a7"),
    ],
)
def test_snefru_official_vectors(bits: int, rounds: int, expected: str) -> None:
    assert run("Snefru", "Hello, World!", [bits, rounds]) == expected


def test_snefru_supports_all_official_digest_sizes() -> None:
    for bits in range(32, 481, 32):
        assert len(run("Snefru", b"size", [bits, 8])) == bits // 4


@pytest.mark.parametrize(
    ("message", "key", "expected"),
    [
        (
            "Hello, World!",
            "",
            "ce5effce32637e6b8edaacc9284b873c3fd4e66f9779a79df67eb4a82dda8230",
        ),
        (
            "Head Over Heels",
            "arty",
            "d8f7fe4931fbaa37316f76283d5f615f50ddd54afdc794b61da522556aee99ad",
        ),
    ],
)
def test_md6_cyberchef_vectors(message: str, key: str, expected: str) -> None:
    assert run("MD6", message, [256, 64, key]) == expected


def test_md6_all_digest_sizes_and_levels() -> None:
    assert run("MD6", "message", [0, 0, ""]) == run("MD6", "message", [1, 0, ""])
    assert len(run("MD6", "message", [512, 1_000, "key"])) == 128


def test_generate_all_hashes_and_checksums() -> None:
    hashes = run("Generate all hashes", "abc")
    assert "MD5:          900150983cd24fb0d6963f7d28e17f72" in hashes
    assert "SHA2 256:     ba7816bf" in hashes
    assert "SSDEEP:" in hashes
    checksums = run("Generate all checksums", "abc")
    assert "CRC-32:                   352441c2" in checksums
    assert all(name in checksums for name in ("Adler-32", "Fletcher-8", "Fletcher-64"))


def gost_args(mode: str, padding: str = "BIT") -> list[object]:
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
    # CyberChef's GOST backend accepts short keys and zero-fills missing words.
    assert run("GOST Encrypt", "12345678", [toggle(b"short")])


def test_gost_sign_verify_and_key_wrap() -> None:
    key = toggle(bytes(range(32)))
    iv = toggle(b"12345678")
    signature = run("GOST Sign", "message", [key, iv, "Raw", "Hex", "GOST 28147 (1989)", "E-A", 32])
    verify_args = [
        key,
        iv,
        {"option": "Hex", "string": signature},
        "Raw",
        "GOST 28147 (1989)",
        "E-A",
    ]
    assert run("GOST Verify", "message", verify_args) == "The signature matches"
    assert run("GOST Verify", "changed", verify_args) == "The signature does not match"


def test_gost_official_cyberchef_vectors() -> None:
    short_key = toggle(bytes.fromhex("00112233"))
    iv64 = toggle(bytes.fromhex("0011223344556677"))
    iv128 = toggle(bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert (
        run(
            "GOST Encrypt",
            "Hello, World!",
            [short_key, iv64, "Raw", "Hex", "GOST 28147 (1989)", "E-SC", "OFB", "CP", "ZERO"],
        )
        == "f124ac5c0853870906dbaf9b56"
    )
    encrypted = run(
        "GOST Encrypt",
        "Hello, World!",
        [
            short_key,
            iv128,
            "Raw",
            "Hex",
            "GOST R 34.12 (Kuznyechik, 2015)",
            "E-SC",
            "CBC",
            "CP",
            "PKCS5",
        ],
    )
    assert encrypted == "8673d490dfa4a66d5e3ff00ba316724f"
    assert (
        run(
            "GOST Decrypt",
            encrypted,
            [
                short_key,
                iv128,
                "Hex",
                "Raw",
                "GOST R 34.12 (Kuznyechik, 2015)",
                "E-TEST",
                "CBC",
                "CP",
                "PKCS5",
            ],
        )
        == b"Hello, World!\0\0\0"
    )
    assert (
        run(
            "GOST Sign",
            "Hello, World!",
            [short_key, iv64, "Raw", "Hex", "GOST 28147 (1989)", "E-C", 48],
        )
        == "810d0c40e965"
    )
    assert (
        run(
            "GOST Verify",
            "Hello, World!",
            [
                short_key,
                iv128,
                toggle(bytes.fromhex("42b77fb3d6f6bf04")),
                "Raw",
                "GOST R 34.12 (Kuznyechik, 2015)",
                "E-TEST",
            ],
        )
        == "The signature matches"
    )
    assert run(
        "GOST Key Wrap",
        "Hello, World!123",
        [
            short_key,
            iv64,
            "Raw",
            "Hex",
            "GOST R 34.12 (Magma, 2015)",
            "E-TEST",
            "CP",
        ],
    ) == ("0bb706e92487fceef97589911faeb28200000000000000000000000000000000\r\n6b7bfd16")
    assert (
        run(
            "GOST Key Unwrap",
            "c8e58458a42d21974d50103d59b469f2c8e58458a42d21974d50103d59b469f2\r\na32a1575",
            [
                toggle(b""),
                toggle(b"00112233", "Latin1"),
                "Hex",
                "Raw",
                "GOST 28147 (1989)",
                "E-Z",
                "CP",
            ],
        )
        == b"0123456789abcdef0123456789abcdef"
    )


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("", "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"),
        (
            "This is message, length=32 bytes",
            "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
        ),
    ],
)
def test_gost94_official_vectors(message: str, expected: str) -> None:
    assert run("GOST Hash", message, ["GOST 28147 (1994)", "256", "D-A"]) == expected


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


@pytest.mark.parametrize(
    ("key_size", "ciphertext"),
    [
        (16, "9f589f5cf6122c32b6bfec2f2ae8c35a"),
        (24, "efa71f788965bd4453f860178fc19101"),
        (32, "57ff739d4dc92c1bd7fc01700cc8216f"),
    ],
)
def test_twofish_official_zero_vectors(key_size: int, ciphertext: str) -> None:
    key = toggle(bytes(key_size))
    encrypt_args = [key, toggle(b""), "ECB", "Hex", "Hex", "NO"]
    decrypt_args = [key, toggle(b""), "ECB", "Hex", "Hex", "NO"]
    assert run("Twofish Encrypt", "00" * 16, encrypt_args) == ciphertext
    assert run("Twofish Decrypt", ciphertext, decrypt_args) == "00" * 16


@pytest.mark.parametrize("mode", ["CFB", "OFB", "CTR"])
def test_twofish_official_stream_mode_options(mode: str) -> None:
    key = toggle(bytes(range(16)))
    iv = toggle(bytes(range(16, 32)))
    plaintext = b"partial final block exercises stream handling"
    encrypt_args = [key, iv, mode, "Raw", "Hex", "NO"]
    decrypt_args = [key, iv, mode, "Hex", "Raw", "NO"]
    ciphertext = run("Twofish Encrypt", plaintext, encrypt_args)
    assert isinstance(ciphertext, str)
    assert run("Twofish Decrypt", ciphertext, decrypt_args) == plaintext


@pytest.mark.parametrize("padding", ["PKCS5", "BIT"])
def test_twofish_official_block_padding_options(padding: str) -> None:
    key = toggle(bytes(range(16)))
    iv = toggle(bytes(range(16, 32)))
    encrypt_args = [key, iv, "CBC", "Raw", "Hex", padding]
    decrypt_args = [key, iv, "CBC", "Hex", "Raw", padding]
    ciphertext = run("Twofish Encrypt", b"not block aligned", encrypt_args)
    assert run("Twofish Decrypt", ciphertext, decrypt_args) == b"not block aligned"
