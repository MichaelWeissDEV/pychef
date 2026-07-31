"""RFC 4503 and CyberChef Rabbit vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_ZERO_INPUT = "00" * 48


@pytest.mark.parametrize(
    ("key", "iv", "expected"),
    [
        (
            "00000000000000000000000000000000",
            "",
            "b15754f036a5d6ecf56b45261c4af70288e8d815c59c0c397b696c4789c68aa7"
            "f416a1c3700cd451da68d1881673d696",
        ),
        (
            "912813292e3d36fe3bfc62f1dc51c3ac",
            "",
            "3d2df3c83ef627a1e97fc38487e2519cf576cd61f4405b8896bf53aa8554fc19"
            "e5547473fbdb43508ae53b20204d4c5e",
        ),
        (
            "8395741587e0c733e9e9ab01c09b0043",
            "",
            "0cb10dcda041cdac32eb5cfd02d0609b95fc9fca0f17015a7b7092114cff3ead9"
            "649e5de8bfc7f3f924147ad3a947428",
        ),
        (
            "00000000000000000000000000000000",
            "0000000000000000",
            "c6a7275ef85495d87ccd5d376705b7ed5f29a6ac04f5efd47b8f293270dc4a8d"
            "2ade822b29de6c1ee52bdb8a47bf8f66",
        ),
        (
            "00000000000000000000000000000000",
            "c373f575c1267e59",
            "1fcd4eb9580012e2e0dccc9222017d6da75f4e10d12125017b2499ffed936f2e"
            "ebc112c393e738392356bdd012029ba7",
        ),
        (
            "00000000000000000000000000000000",
            "a6eb561ad2f41727",
            "445ad8c805858dbf70b6af23a151104d96c8f27947f42c5baeae67c6acc35b03"
            "9fcbfc895fa71c17313df034f01551cb",
        ),
    ],
)
def test_rabbit_official_rfc_vectors(key: str, iv: str, expected: str) -> None:
    args = [
        {"option": "Hex", "string": key},
        {"option": "Hex", "string": iv},
        "Big",
        "Hex",
        "Hex",
    ]
    assert bake(_ZERO_INPUT, [{"op": "Rabbit", "args": args}]) == expected
    assert bake(expected, [{"op": "Rabbit", "args": args}]) == _ZERO_INPUT


def test_rabbit_official_xor_partial_and_little_endian_vectors() -> None:
    big_args = [
        {"option": "Hex", "string": "00" * 16},
        {"option": "Hex", "string": ""},
        "Big",
        "Hex",
        "Hex",
    ]
    assert bake(
        "cedda96c054e3ddd93da7ed05e2a4b7bdb0c00fe214f03502e2708b2c2bfc77a"
        "a2311b0b9af8aa78d119f92b26db0a6b",
        [{"op": "Rabbit", "args": big_args}],
    ) == (
        "7f8afd9c33ebeb3166b13bf64260bc7953e4d8ebe4d30f69554e64f54b794ddd"
        "5627bac8eaf47e290b7128a330a8dcfd"
    )
    assert bake("00" * 8, [{"op": "Rabbit", "args": big_args}]) == "f56b45261c4af702"

    little_args = [
        {"option": "Hex", "string": "23c2731e8b5469fd8dabb5bc592a0f3a"},
        {"option": "Hex", "string": "712906405ef03201"},
        "Little",
        "Raw",
        "Hex",
    ]
    assert bake("Rabbit stream cipher test", [{"op": "Rabbit", "args": little_args}]) == (
        "1ae2d4edcf9b6063b00fd6fda0b223aded157e77031cf0440b"
    )


def test_rabbit_validates_key_iv_and_supports_raw_output() -> None:
    with pytest.raises(OperationError, match="Invalid key length: 8"):
        bake("", [{"op": "Rabbit", "args": [{"option": "Hex", "string": "00" * 8}]}])
    with pytest.raises(OperationError, match="Invalid IV length: 4"):
        bake(
            "",
            [
                {
                    "op": "Rabbit",
                    "args": [
                        {"option": "Hex", "string": "00" * 16},
                        {"option": "Hex", "string": "00" * 4},
                    ],
                }
            ],
        )
    args = [
        {"option": "UTF8", "string": "0123456789abcdef"},
        {"option": "UTF8", "string": "12345678"},
        "Little",
        "Raw",
        "Raw",
    ]
    encrypted = bake("raw Rabbit", [{"op": "Rabbit", "args": args}])
    assert isinstance(encrypted, bytes)
    assert bake(encrypted, [{"op": "Rabbit", "args": args}]) == b"raw Rabbit"
