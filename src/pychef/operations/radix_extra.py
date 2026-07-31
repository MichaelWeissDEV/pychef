"""Base92 and Bech32/Bech32m encodings without runtime dependencies."""

from __future__ import annotations

import json
import re

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_REVERSE = {character: index for index, character in enumerate(_BECH32_CHARSET)}
_BECH32_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _base92_character(value: int) -> str:
    if value == 0:
        return "!"
    if 1 <= value <= 61:
        return chr(ord("#") + value - 1)
    if 62 <= value < 91:
        return chr(ord("a") + value - 62)
    raise ValueError("invalid Base92 value")


def _base92_value(character: str) -> int:
    if character == "!":
        return 0
    if "#" <= character <= "_":
        return ord(character) - ord("#") + 1
    if "a" <= character <= "}":
        return ord(character) - ord("a") + 62
    raise ValueError(f"{character} is not a base92 character")


@operation("To Base92", category="Encoding")
def to_base92(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    output: list[str] = []
    accumulator = 0
    bits = 0
    for byte in data:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 13:
            bits -= 13
            pair = (accumulator >> bits) & 0x1FFF
            output.extend((_base92_character(pair // 91), _base92_character(pair % 91)))
            accumulator &= (1 << bits) - 1
    if bits:
        if bits < 7:
            output.append(_base92_character((accumulator << (6 - bits)) & 0x3F))
        else:
            pair = (accumulator << (13 - bits)) & 0x1FFF
            output.extend((_base92_character(pair // 91), _base92_character(pair % 91)))
    return "".join(output)


@operation("From Base92", category="Encoding")
def from_base92(value: Data, _args: Args) -> bytes:
    text = to_text(value)
    output = bytearray()
    accumulator = 0
    bits = 0
    for index in range(0, len(text), 2):
        if index + 1 < len(text):
            number = _base92_value(text[index]) * 91 + _base92_value(text[index + 1])
            width = 13
        else:
            number = _base92_value(text[index])
            width = 6
        accumulator = (accumulator << width) | number
        bits += width
        while bits >= 8:
            bits -= 8
            output.append((accumulator >> bits) & 0xFF)
            accumulator &= (1 << bits) - 1
    return bytes(output)


def _bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(_BECH32_GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(character) >> 5 for character in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: list[int], from_width: int, to_width: int, *, pad: bool) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    maximum = (1 << to_width) - 1
    for value in data:
        if value < 0 or value >= 1 << from_width:
            raise ValueError("value exceeds source bit width")
        accumulator = (accumulator << from_width) | value
        bits += from_width
        while bits >= to_width:
            bits -= to_width
            result.append((accumulator >> bits) & maximum)
    if pad and bits:
        result.append((accumulator << (to_width - bits)) & maximum)
    elif bits >= from_width or ((accumulator << (to_width - bits)) & maximum):
        raise ValueError("invalid padding in Bech32 data")
    return result


def _bech32_checksum(hrp: str, words: list[int], encoding: str) -> list[int]:
    constant = 0x2BC830A3 if encoding == "Bech32m" else 1
    value = _bech32_polymod(_bech32_hrp_expand(hrp) + words + [0] * 6) ^ constant
    return [(value >> (5 * (5 - index))) & 31 for index in range(6)]


def _bech32_encode(hrp: str, data: bytes, encoding: str, segwit: bool, version: int) -> str:
    if not hrp:
        raise ValueError("Human-Readable Part (HRP) cannot be empty.")
    if any(not 33 <= ord(character) <= 126 for character in hrp):
        raise ValueError("HRP may only contain printable ASCII characters")
    hrp = hrp.lower()
    if segwit:
        if not 0 <= version <= 16:
            raise ValueError("witness version must be between 0 and 16")
        if not 2 <= len(data) <= 40 or (version == 0 and len(data) not in {20, 32}):
            raise ValueError("invalid witness program length")
        words = [version, *_convert_bits(list(data), 8, 5, pad=True)]
    else:
        words = _convert_bits(list(data), 8, 5, pad=True)
    encoded = (
        hrp
        + "1"
        + "".join(_BECH32_CHARSET[word] for word in words + _bech32_checksum(hrp, words, encoding))
    )
    if len(encoded) > 90:
        raise ValueError("encoded Bech32 string exceeds 90 characters")
    return encoded


@operation("To Bech32", category="Encoding")
def to_bech32(value: Data, args: Args) -> str:
    hrp = str(arg(args, 0, "bc"))
    encoding = str(arg(args, 1, "Bech32"))
    input_format = str(arg(args, 2, "Raw bytes"))
    mode = str(arg(args, 3, "Generic"))
    version = require_int(arg(args, 4, 0), name="witness version")
    data = (
        bytes.fromhex(re.sub(r"\s+", "", to_text(value)))
        if input_format == "Hex"
        else to_bytes(value)
    )
    return _bech32_encode(hrp, data, encoding, mode == "Bitcoin SegWit", version)


def _bech32_decode(value: str, requested_encoding: str) -> tuple[str, str, bytes, int | None]:
    if len(value) > 90:
        raise ValueError("Bech32 string exceeds 90 characters")
    if value.lower() != value and value.upper() != value:
        raise ValueError("mixed case is not allowed in Bech32")
    value = value.lower()
    separator = value.rfind("1")
    if separator <= 0 or separator + 7 > len(value):
        raise ValueError("invalid Bech32 separator or data length")
    hrp = value[:separator]
    try:
        data = [_BECH32_REVERSE[character] for character in value[separator + 1 :]]
    except KeyError as exc:
        raise ValueError(f"invalid Bech32 character: {exc.args[0]}") from exc
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    detected = "Bech32" if polymod == 1 else "Bech32m" if polymod == 0x2BC830A3 else ""
    if not detected or (requested_encoding != "Auto-detect" and detected != requested_encoding):
        raise ValueError("invalid Bech32 checksum")
    words = data[:-6]
    version: int | None = None
    segwit_hrps = {"bc", "tb", "ltc", "tltc", "bcrt"}
    if hrp in segwit_hrps and words and words[0] <= 16:
        try:
            candidate = bytes(_convert_bits(words[1:], 5, 8, pad=False))
        except ValueError:
            decoded = bytes(_convert_bits(words, 5, 8, pad=False))
        else:
            if (words[0] == 0 and len(candidate) in {20, 32}) or (
                words[0] != 0 and 2 <= len(candidate) <= 40
            ):
                version = words[0]
                decoded = bytes([version]) + candidate
            else:
                decoded = bytes(_convert_bits(words, 5, 8, pad=False))
    else:
        decoded = bytes(_convert_bits(words, 5, 8, pad=False))
    return hrp, detected, decoded, version


@operation("From Bech32", category="Encoding")
def from_bech32(value: Data, args: Args) -> Data:
    text = to_text(value).strip()
    if not text:
        return ""
    requested = str(arg(args, 0, "Auto-detect"))
    output_format = str(arg(args, 1, "Raw"))
    hrp, encoding, data, version = _bech32_decode(text, requested)
    if output_format == "Raw":
        return data
    hexadecimal = data.hex()
    if output_format == "HRP: Hex":
        return f"{hrp}: {hexadecimal}"
    if output_format == "JSON":
        return json.dumps({"hrp": hrp, "encoding": encoding, "data": hexadecimal}, indent=2)
    if output_format == "Bitcoin scriptPubKey" and version is not None and len(data) >= 2:
        opcode = 0 if version == 0 else 0x50 + version
        program = data[1:]
        return bytes([opcode, len(program)]).hex() + program.hex()
    return hexadecimal
