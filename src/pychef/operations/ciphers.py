"""Classical ciphers and lightweight pure-Python stream ciphers."""

from __future__ import annotations

import math
import string

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, require_int


def _rotate_alphabet(character: str, amount: int, alphabet: str) -> str:
    try:
        index = alphabet.index(character)
    except ValueError:
        return character
    return alphabet[(index + amount) % len(alphabet)]


@operation("ROT13", category="Ciphers")
def rot13(value: Data, args: Args) -> str:
    rotate_lower = bool(arg(args, 0, True))
    rotate_upper = bool(arg(args, 1, True))
    rotate_numbers = bool(arg(args, 2, False))
    amount = require_int(arg(args, 3, 13))
    output = ""
    for character in to_text(value):
        if rotate_lower and character in string.ascii_lowercase:
            character = _rotate_alphabet(character, amount, string.ascii_lowercase)
        elif rotate_upper and character in string.ascii_uppercase:
            character = _rotate_alphabet(character, amount, string.ascii_uppercase)
        elif rotate_numbers and character in string.digits:
            character = _rotate_alphabet(character, amount, string.digits)
        output += character
    return output


@operation("ROT47", category="Ciphers")
def rot47(value: Data, args: Args) -> str:
    amount = require_int(arg(args, 0, 47))
    return "".join(
        chr(33 + ((ord(character) - 33 + amount) % 94))
        if 33 <= ord(character) <= 126
        else character
        for character in to_text(value)
    )


@operation("ROT8000", category="Ciphers")
def rot8000(value: Data, _args: Args) -> str:
    transitions = (
        (33, True),
        (127, False),
        (161, True),
        (5760, False),
        (5761, True),
        (8192, False),
        (8203, True),
        (8232, False),
        (8234, True),
        (8239, False),
        (8240, True),
        (8287, False),
        (8288, True),
        (12288, False),
        (12289, True),
        (55296, False),
        (57344, True),
    )
    valid: list[int] = []
    enabled = False
    transition_map = dict(transitions)
    for codepoint in range(0x10000):
        enabled = transition_map.get(codepoint, enabled)
        if enabled:
            valid.append(codepoint)
    indexes = {codepoint: index for index, codepoint in enumerate(valid)}
    amount = len(valid) // 2
    return "".join(
        chr(valid[(indexes[ord(character)] + amount) % len(valid)])
        if ord(character) in indexes
        else character
        for character in to_text(value)
    )


def _affine(value: Data, multiplier: int, shift: int) -> str:
    output = ""
    for character in to_text(value):
        if character.isascii() and character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            character = chr(base + (multiplier * (ord(character) - base) + shift) % 26)
        output += character
    return output


@operation("Affine Cipher Encode", category="Ciphers")
def affine_encode(value: Data, args: Args) -> str:
    return _affine(value, require_int(arg(args, 0, 1)), require_int(arg(args, 1, 0)))


@operation("Affine Cipher Decode", category="Ciphers")
def affine_decode(value: Data, args: Args) -> str:
    multiplier = require_int(arg(args, 0, 1))
    inverse = pow(multiplier, -1, 26)
    shift = require_int(arg(args, 1, 0))
    return _affine(value, inverse, -inverse * shift)


@operation("Atbash Cipher", category="Ciphers")
def atbash(value: Data, _args: Args) -> str:
    return _affine(value, 25, 25)


@operation("A1Z26 Cipher Encode", category="Ciphers")
def a1z26_encode(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Space"), " ")
    return delimiter.join(
        str(ord(character.lower()) - 96)
        for character in to_text(value)
        if character.isascii() and character.isalpha()
    )


@operation("A1Z26 Cipher Decode", category="Ciphers")
def a1z26_decode(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Space"), " ")
    if not to_text(value):
        return ""
    numbers = to_text(value).split(delimiter)
    if any(not number.isdigit() or not 1 <= int(number) <= 26 for number in numbers):
        raise ValueError("all numbers must be between 1 and 26")
    return "".join(chr(96 + int(number)) for number in numbers)


def _vigenere(value: Data, key: str, decode: bool) -> str:
    shifts = [
        ord(character.lower()) - 97
        for character in key
        if character.isascii() and character.isalpha()
    ]
    if not shifts:
        raise ValueError("key must contain at least one alphabetic character")
    output = ""
    position = 0
    for character in to_text(value):
        if character.isascii() and character.isalpha():
            shift = shifts[position % len(shifts)] * (-1 if decode else 1)
            alphabet = string.ascii_uppercase if character.isupper() else string.ascii_lowercase
            character = _rotate_alphabet(character, shift, alphabet)
            position += 1
        output += character
    return output


@operation("Vigenère Encode", category="Ciphers")
def vigenere_encode(value: Data, args: Args) -> str:
    return _vigenere(value, str(arg(args, 0, "")), False)


@operation("Vigenère Decode", category="Ciphers")
def vigenere_decode(value: Data, args: Args) -> str:
    return _vigenere(value, str(arg(args, 0, "")), True)


@operation("Caesar Box Cipher", category="Ciphers")
def caesar_box(value: Data, args: Args) -> str:
    height = require_int(arg(args, 0, 1), name="box height")
    if height < 1:
        raise ValueError("box height must be positive")
    text = to_text(value).replace(" ", "")
    width = math.ceil(len(text) / height)
    text = text.ljust(height * width, "\0")
    return "".join(
        text[index]
        for row in range(height)
        for index in range(row, len(text), height)
        if text[index] != "\0"
    )


def _rail_pattern(length: int, rails: int, offset: int) -> list[int]:
    if rails < 2:
        raise ValueError("key has to be at least 2")
    cycle = (rails - 1) * 2
    return [rails - 1 - abs(cycle // 2 - (position + offset) % cycle) for position in range(length)]


@operation("Rail Fence Cipher Encode", category="Ciphers")
def rail_fence_encode(value: Data, args: Args) -> str:
    text = to_text(value)
    rails = require_int(arg(args, 0, 2))
    offset = require_int(arg(args, 1, 0))
    pattern = _rail_pattern(len(text), rails, offset)
    return "".join(
        text[index] for rail in range(rails) for index, row in enumerate(pattern) if row == rail
    )


@operation("Rail Fence Cipher Decode", category="Ciphers")
def rail_fence_decode(value: Data, args: Args) -> str:
    text = to_text(value)
    rails = require_int(arg(args, 0, 2))
    offset = require_int(arg(args, 1, 0))
    pattern = _rail_pattern(len(text), rails, offset)
    positions = sorted(range(len(text)), key=lambda index: pattern[index])
    output = [""] * len(text)
    for character, position in zip(text, positions, strict=True):
        output[position] = character
    return "".join(output)


@operation("Bacon Cipher Encode", category="Ciphers")
def bacon_encode(value: Data, args: Args) -> str:
    alphabet_name = str(arg(args, 0, "Standard (I=J and U=V)"))
    translation = str(arg(args, 1, "A/B"))
    keep_extra = bool(arg(args, 2, False))
    invert = bool(arg(args, 3, False))
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if alphabet_name == "Complete" else "ABCDEFGHIKLMNOPQRSTUWXYZ"
    )
    mapping = {character: index for index, character in enumerate(alphabet)}
    if alphabet_name != "Complete":
        mapping.update({"J": mapping["I"], "V": mapping["U"]})
    zero, one = ("0", "1") if translation == "0/1" else ("A", "B")
    if invert:
        zero, one = one, zero
    output: list[str] = []
    for character in to_text(value):
        index = mapping.get(character.upper())
        if index is None:
            if keep_extra:
                output.append(character)
        else:
            output.append(f"{index:05b}".replace("0", zero).replace("1", one))
    return "".join(output)


@operation("Bacon Cipher Decode", category="Ciphers")
def bacon_decode(value: Data, args: Args) -> str:
    alphabet_name = str(arg(args, 0, "Standard (I=J and U=V)"))
    translation = str(arg(args, 1, "A/B"))
    invert = bool(arg(args, 2, False))
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if alphabet_name == "Complete" else "ABCDEFGHIKLMNOPQRSTUWXYZ"
    )
    text = to_text(value)
    if translation == "Case":
        bits = "".join(
            "1" if character.isupper() else "0" for character in text if character.isalpha()
        )
    else:
        zero, one = ("0", "1") if translation == "0/1" else ("A", "B")
        bits = "".join(
            "0" if character.upper() == zero else "1"
            for character in text
            if character.upper() in {zero, one}
        )
    if invert:
        bits = bits.translate(str.maketrans("01", "10"))
    return "".join(
        alphabet[int(bits[index : index + 5], 2)]
        for index in range(0, len(bits) - 4, 5)
        if int(bits[index : index + 5], 2) < len(alphabet)
    )


@operation("Cetacean Cipher Encode", category="Ciphers")
def cetacean_encode(value: Data, _args: Args) -> str:
    return "".join(
        " " if character == " " else f"{ord(character):016b}".translate(str.maketrans("01", "Ee"))
        for character in to_text(value)
    )


@operation("Cetacean Cipher Decode", category="Ciphers")
def cetacean_decode(value: Data, _args: Args) -> str:
    bits = "".join(
        "0000000000100000" if character == " " else ("1" if character == "e" else "0")
        for character in to_text(value)
    )
    return "".join(
        chr(int(bits[index : index + 16], 2))
        for index in range(0, len(bits), 16)
        if len(bits[index : index + 16]) == 16
    )


@operation("Encode NetBIOS Name", category="Ciphers")
def encode_netbios(value: Data, args: Args) -> bytes:
    offset = require_int(arg(args, 0, 65))
    data = to_bytes(value)
    if len(data) > 16:
        return b""
    data = data.ljust(16, b" ")
    return bytes(part for byte in data for part in ((byte >> 4) + offset, (byte & 0xF) + offset))


@operation("Decode NetBIOS Name", category="Ciphers")
def decode_netbios(value: Data, args: Args) -> bytes:
    offset = require_int(arg(args, 0, 65))
    data = to_bytes(value)
    if len(data) > 32 or len(data) % 2:
        return b""
    return bytes(
        (((data[index] - offset) << 4) | ((data[index + 1] - offset) & 0xF))
        for index in range(0, len(data), 2)
    ).rstrip(b" ")


@operation("Citrix CTX1 Encode", category="Ciphers")
def citrix_ctx1_encode(value: Data, _args: Args) -> bytes:
    output = bytearray()
    previous = 0
    for byte in to_text(value).encode("utf-16le"):
        previous = byte ^ 0xA5 ^ previous
        output.extend(((previous >> 4) + 0x41, (previous & 0xF) + 0x41))
    return bytes(output)


@operation("Citrix CTX1 Decode", category="Ciphers")
def citrix_ctx1_decode(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    if len(data) % 4:
        raise ValueError("incorrect hash length")
    encoded = bytes(
        (((data[index] - 0x41) << 4) | (data[index + 1] - 0x41)) for index in range(0, len(data), 2)
    )
    output = bytearray()
    previous = 0
    for byte in encoded:
        output.append(byte ^ 0xA5 ^ previous)
        previous = byte
    return output.decode("utf-16le")


_MORSE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "/": "-..-.",
    "-": "-....-",
    "(": "-.--.",
    ")": "-.--.-",
}


@operation("To Morse Code", category="Ciphers")
def to_morse(value: Data, args: Args) -> str:
    style = str(arg(args, 0, "-/ ."))
    letter_delimiter = char_rep(arg(args, 1, "Space"), " ")
    word_delimiter = char_rep(arg(args, 2, "Forward slash"), "/")
    encoded_words = [
        letter_delimiter.join(
            _MORSE[character] for character in word.upper() if character in _MORSE
        )
        for word in to_text(value).split()
    ]
    output = word_delimiter.join(encoded_words)
    if style == "_/.":
        return output.replace("-", "_")
    if style == "Dash/Dot":
        return output.replace("-", "Dash").replace(".", "Dot")
    if style == "DASH/DOT":
        return output.replace("-", "DASH").replace(".", "DOT")
    if style == "dash/dot":
        return output.replace("-", "dash").replace(".", "dot")
    return output


@operation("From Morse Code", category="Ciphers")
def from_morse(value: Data, args: Args) -> str:
    letter_delimiter = char_rep(arg(args, 0, "Space"), " ")
    word_delimiter = char_rep(arg(args, 1, "Forward slash"), "/")
    reverse = {code: character for character, code in _MORSE.items()}
    text = to_text(value).replace("_", "-")
    return " ".join(
        "".join(reverse.get(code, "") for code in word.split(letter_delimiter))
        for word in text.split(word_delimiter)
    )


@operation("RC4", category="Ciphers")
def rc4(value: Data, args: Args) -> bytes:
    key_value = arg(args, 0, {"string": "", "option": "Hex"})
    if isinstance(key_value, dict):
        key_text = str(key_value.get("string", ""))
        option = str(key_value.get("option", "Hex"))
        key = (
            bytes.fromhex(key_text)
            if option == "Hex"
            else key_text.encode("latin-1" if option == "Latin1" else "utf-8")
        )
    else:
        key = to_bytes(str(key_value))
    if not key:
        raise ValueError("key must not be empty")
    state = list(range(256))
    index = 0
    for position in range(256):
        index = (index + state[position] + key[position % len(key)]) % 256
        state[position], state[index] = state[index], state[position]
    output = bytearray()
    left = right = 0
    for byte in to_bytes(value):
        left = (left + 1) % 256
        right = (right + state[left]) % 256
        state[left], state[right] = state[right], state[left]
        output.append(byte ^ state[(state[left] + state[right]) % 256])
    return bytes(output)


_NATO = dict(
    zip(
        string.ascii_uppercase,
        [
            "Alfa",
            "Bravo",
            "Charlie",
            "Delta",
            "Echo",
            "Foxtrot",
            "Golf",
            "Hotel",
            "India",
            "Juliett",
            "Kilo",
            "Lima",
            "Mike",
            "November",
            "Oscar",
            "Papa",
            "Quebec",
            "Romeo",
            "Sierra",
            "Tango",
            "Uniform",
            "Victor",
            "Whiskey",
            "X-ray",
            "Yankee",
            "Zulu",
        ],
        strict=True,
    )
)
_NATO.update(
    dict(
        zip(
            string.digits,
            ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"],
            strict=True,
        )
    )
)
_NATO.update({",": "Comma", "/": "Fraction bar", ".": "Full stop"})


@operation("Convert to NATO alphabet", category="Text")
def nato_alphabet(value: Data, _args: Args) -> str:
    return "".join(
        (_NATO[character.upper()] + " ") if character.upper() in _NATO else character
        for character in to_text(value)
    )
