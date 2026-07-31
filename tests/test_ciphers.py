"""Classical cipher compatibility and round-trip tests."""

from __future__ import annotations

import pytest

from pychef import bake


@pytest.mark.parametrize(
    ("input_value", "args", "expected"),
    [
        (
            "The Quick Brown Fox. 0123456789",
            [True, True, True, 13],
            "Gur Dhvpx Oebja Sbk. 3456789012",
        ),
        (
            "The Quick Brown Fox. 0123456789",
            [True, False, False, 13],
            "Tur Qhvpx Bebja Fbk. 0123456789",
        ),
        (
            "The Quick Brown Fox. 0123456789",
            [False, True, False, 13],
            "Ghe Duick Orown Sox. 0123456789",
        ),
        ("abcXYZ09", [True, True, True, -13], "nopKLM76"),
    ],
)
def test_rot13_official_behavior(input_value: str, args: list[object], expected: str) -> None:
    assert bake(input_value, [{"op": "ROT13", "args": args}]) == expected


def test_rot47_and_rot8000_are_involutions() -> None:
    source = "Hello, 世界!"
    assert bake(bake(source, ["ROT47"]), ["ROT47"]) == source
    assert bake(bake(source, ["ROT8000"]), ["ROT8000"]) == source


def test_affine_atbash_and_a1z26() -> None:
    encoded = bake("Affine Cipher", [{"op": "Affine Cipher Encode", "args": [5, 8]}])
    assert bake(encoded, [{"op": "Affine Cipher Decode", "args": [5, 8]}]) == "Affine Cipher"
    assert bake("Abc-Z", ["Atbash Cipher"]) == "Zyx-A"
    numbers = bake("abc xyz", [{"op": "A1Z26 Cipher Encode", "args": ["Hyphen"]}])
    assert numbers == "1-2-3-24-25-26"
    assert bake(numbers, [{"op": "A1Z26 Cipher Decode", "args": ["Hyphen"]}]) == "abcxyz"


def test_vigenere_known_vector() -> None:
    encoded = bake("ATTACKATDAWN", [{"op": "Vigenère Encode", "args": ["LEMON"]}])
    assert encoded == "LXFOPVEFRNHR"
    assert bake(encoded, [{"op": "Vigenère Decode", "args": ["LEMON"]}]) == "ATTACKATDAWN"


def test_transposition_ciphers_round_trip() -> None:
    source = "WEAREDISCOVEREDFLEEATONCE"
    encoded = bake(source, [{"op": "Rail Fence Cipher Encode", "args": [3, 0]}])
    assert encoded == "WECRLTEERDSOEEFEAOCAIVDEN"
    assert bake(encoded, [{"op": "Rail Fence Cipher Decode", "args": [3, 0]}]) == source
    assert bake("I came I saw", [{"op": "Caesar Box Cipher", "args": [3]}]) == "ImsceaaIw"


def test_bacon_and_cetacean_round_trips() -> None:
    bacon = bake(
        "HELLO", [{"op": "Bacon Cipher Encode", "args": ["Complete", "A/B", False, False]}]
    )
    assert bacon == "AABBB AABAA ABABB ABABB ABBBA".replace(" ", "")
    assert (
        bake(bacon, [{"op": "Bacon Cipher Decode", "args": ["Complete", "A/B", False]}]) == "HELLO"
    )
    whale = bake("hi there", ["Cetacean Cipher Encode"])
    assert bake(whale, ["Cetacean Cipher Decode"]) == "hi there"


def test_netbios_and_ctx1_round_trips() -> None:
    encoded = bake(b"FRED", [{"op": "Encode NetBIOS Name", "args": [65]}])
    assert len(encoded) == 32
    assert bake(encoded, [{"op": "Decode NetBIOS Name", "args": [65]}]) == b"FRED"
    ctx = bake("Password!", ["Citrix CTX1 Encode"])
    assert bake(ctx, ["Citrix CTX1 Decode"]) == "Password!"


def test_morse_and_rc4() -> None:
    morse = bake("SOS HELP", [{"op": "To Morse Code", "args": ["-/.", "Space", "Forward slash"]}])
    assert morse == "... --- .../.... . .-.. .--."
    assert (
        bake(morse, [{"op": "From Morse Code", "args": ["Space", "Forward slash"]}]) == "SOS HELP"
    )
    output = bake(b"Plaintext", [{"op": "RC4", "args": [{"string": "Key", "option": "UTF8"}]}])
    assert isinstance(output, bytes)
    assert output.hex() == "bbf316e8d940af0ad3"
    assert (
        bake(output, [{"op": "RC4", "args": [{"string": "Key", "option": "UTF8"}]}]) == b"Plaintext"
    )


def test_nato_alphabet() -> None:
    assert bake("A1.", ["Convert to NATO alphabet"]) == "Alfa One Full stop "
