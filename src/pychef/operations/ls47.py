"""Pure-Python LS47 (ElsieFour-derived) cipher."""

from __future__ import annotations

import secrets

from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg, require_int

_ALPHABET = "_abcdefghijklmnopqrstuvwxyz.0123456789,-+*/:?!'()"


def _fixed_position(character: str) -> tuple[int, int]:
    position = _ALPHABET.find(character)
    if position < 0:
        raise ValueError(f"Letter {character} is not included in LS47")
    return divmod(position, 7)


def _key_position(key: str, character: str) -> tuple[int, int]:
    position = key.find(character)
    if position < 0:
        raise ValueError(f"Letter {character} is not in the key")
    return divmod(position, 7)


def _at(key: str, position: tuple[int, int]) -> str:
    return key[position[0] * 7 + position[1]]


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    return ((left[0] + right[0]) % 7, (left[1] + right[1]) % 7)


def _subtract(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    return ((left[0] - right[0]) % 7, (left[1] - right[1]) % 7)


def _rotate_right(key: str, row: int, amount: int) -> str:
    start = row * 7
    middle = key[start : start + 7]
    amount %= 7
    rotated = middle[-amount:] + middle[:-amount] if amount else middle
    return key[:start] + rotated + key[start + 7 :]


def _rotate_down(key: str, column: int, amount: int) -> str:
    rows = [list(key[position : position + 7]) for position in range(0, 49, 7)]
    values = [row[column] for row in rows]
    amount %= 7
    rotated = values[-amount:] + values[:-amount] if amount else values
    for row, character in zip(rows, rotated, strict=True):
        row[column] = character
    return "".join("".join(row) for row in rows)


def _derive_key(password: str) -> str:
    key = _ALPHABET
    index = 0
    for character in password:
        row, column = _fixed_position(character)
        key = _rotate_down(_rotate_right(key, index, column), index, row)
        index = (index + 1) % 7
    return key


def _transform(key: str, text: str, *, decrypting: bool) -> str:
    marker = (0, 0)
    output: list[str] = []
    for character in text:
        cipher_position = _key_position(key, character)
        mix = _fixed_position(_at(key, marker))
        if decrypting:
            plain_position = _subtract(cipher_position, mix)
            plain = _at(key, plain_position)
            output.append(plain)
        else:
            plain_position = cipher_position
            cipher_position = _add(plain_position, mix)
            character = _at(key, cipher_position)
            output.append(character)
        key = _rotate_right(key, plain_position[0], 1)
        cipher_position = _key_position(key, character)
        key = _rotate_down(key, cipher_position[1], 1)
        marker = _add(marker, _fixed_position(character))
    return "".join(output)


@implementation("LS47 Encrypt", category="Ciphers")
def ls47_encrypt(value: Data, args: Args) -> str:
    password = str(arg(args, 0, ""))
    padding_size = require_int(arg(args, 1, 10), name="padding")
    signature = str(arg(args, 2, ""))
    padding = "".join(secrets.choice(_ALPHABET) for _ in range(padding_size))
    plaintext = padding + to_text(value) + "---" + signature
    return _transform(_derive_key(password), plaintext, decrypting=False)


@implementation("LS47 Decrypt", category="Ciphers")
def ls47_decrypt(value: Data, args: Args) -> str:
    password = str(arg(args, 0, ""))
    padding_size = require_int(arg(args, 1, 10), name="padding")
    plaintext = _transform(_derive_key(password), to_text(value), decrypting=True)
    return plaintext[padding_size:]
