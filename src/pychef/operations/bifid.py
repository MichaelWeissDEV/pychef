"""Bifid cipher using CyberChef's keyed Polybius square."""

from __future__ import annotations

from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg

_BIFID_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def _square(keyword: str) -> str:
    normalized = keyword.upper().replace("J", "I")
    if normalized and (not normalized.isascii() or not normalized.isalpha()):
        raise ValueError("The key must consist only of letters in the English alphabet")
    return "".join(dict.fromkeys(normalized + _BIFID_ALPHABET))


def _structure(value: str) -> tuple[list[bool | str], list[str]]:
    structure: list[bool | str] = []
    letters: list[str] = []
    for character in value.replace("J", "I").replace("j", "i"):
        if character.upper() in _BIFID_ALPHABET:
            structure.append(character.isupper())
            letters.append(character.upper())
        else:
            structure.append(character)
    return structure, letters


def _restore(structure: list[bool | str], transformed: list[str]) -> str:
    output = ""
    position = 0
    for item in structure:
        if isinstance(item, bool):
            letter = transformed[position]
            output += letter if item else letter.lower()
            position += 1
        else:
            output += item
    return output


@implementation("Bifid Cipher Encode", category="Ciphers")
def bifid_encode(value: Data, args: Args) -> str:
    square = _square(str(arg(args, 0, "")))
    structure, letters = _structure(to_text(value))
    rows: list[int] = []
    columns: list[int] = []
    for letter in letters:
        position = square.index(letter)
        row, column = divmod(position, 5)
        rows.append(row)
        columns.append(column)
    coordinates = rows + columns
    transformed = [
        square[coordinates[index] * 5 + coordinates[index + 1]]
        for index in range(0, len(coordinates), 2)
    ]
    return _restore(structure, transformed)


@implementation("Bifid Cipher Decode", category="Ciphers")
def bifid_decode(value: Data, args: Args) -> str:
    square = _square(str(arg(args, 0, "")))
    structure, letters = _structure(to_text(value))
    coordinates: list[int] = []
    for letter in letters:
        position = square.index(letter)
        coordinates.extend(divmod(position, 5))
    midpoint = len(coordinates) // 2
    transformed = [
        square[coordinates[index] * 5 + coordinates[index + midpoint]] for index in range(midpoint)
    ]
    return _restore(structure, transformed)
