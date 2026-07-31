"""Official CyberChef ChaCha test vectors."""

from __future__ import annotations

from pychef import bake


def test_chacha_rfc8439_official_vector() -> None:
    plaintext = (
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it."
    )
    expected = (
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    args = [
        {
            "option": "Hex",
            "string": "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"
            "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f",
        },
        {"option": "Hex", "string": "00:00:00:00:00:00:00:4a:00:00:00:00"},
        1,
        "20",
        "Raw",
        "Hex",
    ]
    result = bake(plaintext, [{"op": "ChaCha", "args": args}])
    assert isinstance(result, str)
    assert result.replace(" ", "") == expected


def test_chacha_is_symmetric_with_raw_output() -> None:
    args = [
        {"option": "Hex", "string": "00" * 32},
        {"option": "Hex", "string": "00" * 8},
        0,
        "8",
        "Raw",
        "Raw",
    ]
    ciphertext = bake(b"stream cipher", [{"op": "ChaCha", "args": args}])
    assert isinstance(ciphertext, bytes)
    assert bake(ciphertext, [{"op": "ChaCha", "args": args}]) == b"stream cipher"


def test_salsa20_official_ecrypt_prefix() -> None:
    args = [
        {"option": "Hex", "string": "80" + "00" * 31},
        {"option": "Hex", "string": "00" * 8},
        0,
        "20",
        "Hex",
        "Hex",
    ]
    result = bake("00 " * 64, [{"op": "Salsa20", "args": args}])
    assert isinstance(result, str)
    assert result.replace(" ", "") == (
        "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844"
        "b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117"
    )


def test_xsalsa20_official_custom_prefix() -> None:
    args = [
        {"option": "Hex", "string": "".join(f"{value:02x}" for value in range(32))},
        {"option": "Hex", "string": "".join(f"{value:02x}" for value in range(24))},
        0,
        "20",
        "Hex",
        "Hex",
    ]
    result = bake("00 " * 64, [{"op": "XSalsa20", "args": args}])
    assert isinstance(result, str)
    assert result.replace(" ", "") == (
        "7cb660afdd9ec6468f57dd6d2433f93428fd82cd7386c5471a24d8ad2a525b6e"
        "5eff384fc7caa210bb3c8f3e688f4a9752a546df8c253fef17a2679455c7a1e1"
    )
