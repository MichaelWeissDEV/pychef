"""Additional compact binary and presentation encodings."""

from __future__ import annotations

import re

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, expand_alphabet, require_int

_BCD = {
    "8 4 2 1": (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    "7 4 2 1": (0, 1, 2, 3, 4, 5, 6, 8, 9, 10),
    "4 2 2 1": (0, 1, 4, 5, 8, 9, 12, 13, 14, 15),
    "2 4 2 1": (0, 1, 2, 3, 4, 11, 12, 13, 14, 15),
    "8 4 -2 -1": (0, 7, 6, 5, 4, 11, 10, 9, 8, 15),
    "Excess-3": (3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
    "IBM 8 4 2 1": (10, 1, 2, 3, 4, 5, 6, 7, 8, 9),
}
_BRAILLE_ASCII = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)="
_BRAILLE_DOTS = "⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿"


@operation("To Base45", category="Encoding")
def to_base45(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, "0-9A-Z $%*+\\-./:")))
    if len(alphabet) != 45:
        raise ValueError("Base45 alphabet must contain 45 symbols")
    data = to_bytes(value)
    output = ""
    for index in range(0, len(data), 2):
        if index + 1 < len(data):
            number = data[index] * 256 + data[index + 1]
            high, low = divmod(number, 45)
            highest, middle = divmod(high, 45)
            output += alphabet[low] + alphabet[middle] + alphabet[highest]
        else:
            high, low = divmod(data[index], 45)
            output += alphabet[low] + alphabet[high]
    return output


@operation("From Base45", category="Encoding")
def from_base45(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, "0-9A-Z $%*+\\-./:")))
    remove_invalid = bool(arg(args, 1, True))
    text = to_text(value)
    if remove_invalid:
        text = "".join(character for character in text if character in alphabet)
    indexes = {character: index for index, character in enumerate(alphabet)}
    output = bytearray()
    for index in range(0, len(text), 3):
        group = text[index : index + 3]
        if any(character not in indexes for character in group):
            invalid = next(character for character in group if character not in indexes)
            raise ValueError(f"character not in alphabet: {invalid!r}")
        if len(group) == 3:
            number = indexes[group[0]] + indexes[group[1]] * 45 + indexes[group[2]] * 45 * 45
            if number > 0xFFFF:
                raise ValueError(f"triplet too large: {group!r}")
            output.extend(divmod(number, 256))
        elif len(group) == 2:
            number = indexes[group[0]] + indexes[group[1]] * 45
            if number > 0xFF:
                raise ValueError(f"pair too large: {group!r}")
            output.append(number)
        else:
            raise ValueError("invalid Base45 length")
    return bytes(output)


@operation("To COBS", category="Encoding")
def to_cobs(value: Data, _args: Args) -> bytes:
    output = bytearray([0])
    code_index = 0
    code = 1
    for byte in to_bytes(value):
        if byte == 0:
            output[code_index] = code
            code_index = len(output)
            output.append(0)
            code = 1
        else:
            output.append(byte)
            code += 1
            if code == 0xFF:
                output[code_index] = code
                code_index = len(output)
                output.append(0)
                code = 1
    output[code_index] = code
    return bytes(output)


@operation("From COBS", category="Encoding")
def from_cobs(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    output = bytearray()
    index = 0
    while index < len(data):
        code = data[index]
        if code == 0 or index + code > len(data) + 1:
            raise ValueError("invalid COBS data")
        index += 1
        output.extend(data[index : index + code - 1])
        index += code - 1
        if code != 0xFF and index < len(data):
            output.append(0)
    return bytes(output)


@operation("To BCD", category="Encoding")
def to_bcd(value: Data, args: Args) -> Data:
    scheme = _BCD[str(arg(args, 0, "8 4 2 1"))]
    packed = bool(arg(args, 1, True))
    signed = bool(arg(args, 2, False))
    output_format = str(arg(args, 3, "Nibbles"))
    text = to_text(value).strip()
    negative = text.startswith("-")
    digits = text.lstrip("+-")
    if not digits.isdigit():
        raise ValueError("BCD input must be an integer")
    nibbles = [scheme[int(digit)] for digit in digits]
    if signed:
        if packed and len(digits) % 2 == 0:
            nibbles.insert(0, scheme[0])
        nibbles.append(13 if negative else 12)
    if packed:
        encoded = bytes(
            (nibbles[index] << 4) | (nibbles[index + 1] if index + 1 < len(nibbles) else 0)
            for index in range(0, len(nibbles), 2)
        )
        display_nibbles = nibbles
    else:
        encoded = bytes(nibbles)
        display_nibbles = [nibble for encoded_nibble in nibbles for nibble in (0, encoded_nibble)]
    if output_format == "Raw":
        return encoded
    if output_format == "Bytes":
        return " ".join(f"{byte:08b}" for byte in encoded)
    return " ".join(f"{nibble:04b}" for nibble in display_nibbles)


@operation("From BCD", category="Encoding")
def from_bcd(value: Data, args: Args) -> str:
    scheme = _BCD[str(arg(args, 0, "8 4 2 1"))]
    packed = bool(arg(args, 1, True))
    signed = bool(arg(args, 2, False))
    input_format = str(arg(args, 3, "Nibbles"))
    if input_format == "Raw":
        nibbles = [nibble for byte in to_bytes(value) for nibble in (byte >> 4, byte & 15)]
    else:
        bits = re.sub(r"\s+", "", to_text(value))
        nibbles = [int(bits[index : index + 4], 2) for index in range(0, len(bits), 4)]
    if not packed:
        nibbles = nibbles[1::2]
    prefix = ""
    if signed:
        sign = nibbles.pop()
        prefix = "-" if sign in {11, 13} else ""
    reverse = {nibble: str(index) for index, nibble in enumerate(scheme)}
    try:
        digits = "".join(reverse[nibble] for nibble in nibbles).lstrip("0") or "0"
        return prefix + digits if digits != "0" else digits
    except KeyError as exc:
        raise ValueError(f"value {exc.args[0]:04b} is not in the encoding scheme") from exc


@operation("To Braille", category="Encoding")
def to_braille(value: Data, _args: Args) -> str:
    return to_text(value).upper().translate(str.maketrans(_BRAILLE_ASCII, _BRAILLE_DOTS))


@operation("From Braille", category="Encoding")
def from_braille(value: Data, _args: Args) -> str:
    return to_text(value).translate(str.maketrans(_BRAILLE_DOTS, _BRAILLE_ASCII))


@operation("To Hexdump", category="Encoding")
def to_hexdump(value: Data, args: Args) -> str:
    width = require_int(arg(args, 0, 16), name="width")
    uppercase = bool(arg(args, 1, False))
    include_length = bool(arg(args, 2, False))
    unix_format = bool(arg(args, 3, False))
    if width < 1:
        raise ValueError("width must be a positive integer")
    data = to_bytes(value)
    lines: list[str] = []
    for offset in range(0, len(data), width):
        block = data[offset : offset + width]
        hexadecimal = " ".join(f"{byte:02x}" for byte in block).ljust(width * 3)
        printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in block)
        line = f"{offset:08x}  {hexadecimal} |{printable}|"
        lines.append(line.upper() if uppercase and not unix_format else line)
        if include_length and offset + len(block) == len(data):
            lines.append(f"{len(data):08X}" if uppercase else f"{len(data):08x}")
    return "\n".join(lines)


@operation("From Hexdump", category="Encoding")
def from_hexdump(value: Data, _args: Args) -> bytes:
    output = bytearray()
    pattern = re.compile(r"^\s*(?:[0-9A-Fa-f]{4,16}h?:?)?\s+((?:[0-9A-Fa-f]{2}[ -]?)+)")
    for line in to_text(value).splitlines():
        if match := pattern.match(line):
            output.extend(bytes.fromhex(match.group(1).replace("-", " ")))
    return bytes(output)


@operation("To Case Insensitive Regex", category="Encoding")
def to_case_insensitive_regex(value: Data, _args: Args) -> str:
    return re.sub(
        r"(?<!-)([A-Za-z])(?!-)",
        lambda match: f"[{match.group(1).lower()}{match.group(1).upper()}]",
        to_text(value),
    )


@operation("From Case Insensitive Regex", category="Encoding")
def from_case_insensitive_regex(value: Data, _args: Args) -> str:
    return re.sub(
        r"\[([a-z])([A-Z])\]",
        lambda match: (
            match.group(1) if match.group(1).upper() == match.group(2) else match.group(0)
        ),
        to_text(value),
    )


@operation("Unicode Text Format", category="Text")
def unicode_text_format(value: Data, args: Args) -> str:
    underline = bool(arg(args, 0, False))
    strike = bool(arg(args, 1, False))
    suffix = ("\u0336" if strike else "") + ("\u0332" if underline else "")
    return "".join(character + suffix for character in to_text(value))


@operation("Parity Bit", category="Encoding")
def parity_bit(value: Data, args: Args) -> str:
    mode = str(arg(args, 0, "Even Parity"))
    position = str(arg(args, 1, "Start"))
    action = str(arg(args, 2, "Encode"))
    delimiter = str(arg(args, 3, ""))

    def transform(bits: str) -> str:
        if action == "Decode":
            return bits[:-1] if position == "End" else bits[1:]
        if any(bit not in "01 " for bit in bits):
            raise ValueError("unexpected non-binary character")
        parity = "0" if bits.count("1") % 2 == (0 if mode == "Even Parity" else 1) else "1"
        return bits + parity if position == "End" else parity + bits

    if delimiter:
        return delimiter.join(transform(part) for part in to_text(value).split(delimiter))
    return transform(to_text(value))
