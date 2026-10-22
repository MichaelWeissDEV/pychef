"""Binary-to-text encodings and character representation operations.

Portions are behavior-compatible rewrites of CyberChef operations, Crown
Copyright 2016, Apache-2.0. Modified and rewritten in Python for PyChef.
"""

from __future__ import annotations

import base64
import binascii
import html
import html.entities
import quopri
import re
import struct
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
from functools import lru_cache
from urllib.parse import quote, unquote, unquote_plus

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, expand_alphabet, require_int

_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MODHEX = "cbdefghijklnrtuv"
_HEX = re.compile(r"[0-9a-fA-F]")
_NON_HEX = re.compile(r"[^0-9a-fA-F]+")
_Z85_SPEC = r"0-9a-zA-Z.\-:+=^!/*?&<>()[]{}@%$#"
_IPV6_BASE85_SPEC = r"0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~"


def _html_entity_names() -> dict[str, str]:
    """Return CyberChef-compatible canonical HTML5 names by character."""
    candidates: dict[str, list[str]] = {}
    for name, character in html.entities.html5.items():
        if name.endswith(";") and len(character) == 1:
            candidates.setdefault(character, []).append(name[:-1])
    return {
        character: min(names, key=lambda name: (len(name), not name.islower(), name))
        for character, names in candidates.items()
    }


_HTML_ENTITY_NAMES = _html_entity_names()


@lru_cache(maxsize=64)
def _outside(alphabet: str) -> re.Pattern[str]:
    """Pattern matching every character that is not in *alphabet* (cached per alphabet)."""
    return re.compile("[^" + "".join(re.escape(char) for char in sorted(set(alphabet))) + "]+")


def _translate(text: str, source: str, target: str) -> str:
    return text.translate(str.maketrans(source, target))


def _base_n_encode(data: bytes, alphabet: str) -> str:
    if not data:
        return ""
    zero = alphabet[0]
    leading = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    output: list[str] = []
    while number:
        number, remainder = divmod(number, len(alphabet))
        output.append(alphabet[remainder])
    encoded = "".join(reversed(output))
    return zero * leading + encoded


def _base_n_decode(text: str, alphabet: str) -> bytes:
    if not text:
        return b""
    indexes = {character: index for index, character in enumerate(alphabet)}
    number = 0
    for character in text:
        if character not in indexes:
            raise ValueError(f"character {character!r} is not in the alphabet")
        number = number * len(alphabet) + indexes[character]
    leading = len(text) - len(text.lstrip(alphabet[0]))
    size = (number.bit_length() + 7) // 8
    decoded = number.to_bytes(size, "big") if size else b""
    return b"\0" * leading + decoded


@implementation("To Base64", category="Encoding")
def to_base64(value: Data, args: Args) -> str:
    alphabet_spec = str(arg(args, 0, "A-Za-z0-9+/="))
    alphabet = expand_alphabet(alphabet_spec)
    if len(alphabet) not in (64, 65):
        raise ValueError("Base64 alphabet must contain 64 symbols and optional padding")
    result = base64.b64encode(to_bytes(value)).decode("ascii")
    if len(alphabet) == 64:
        result = result.rstrip("=")
        return _translate(result, _BASE64[:64], alphabet)
    return _translate(result, _BASE64, alphabet)


@implementation("From Base64", category="Encoding")
def from_base64(value: Data, args: Args) -> bytes:
    alphabet_spec = str(arg(args, 0, "A-Za-z0-9+/="))
    remove_non_alphabet = bool(arg(args, 1, True))
    strict = bool(arg(args, 2, False))
    alphabet = expand_alphabet(alphabet_spec)
    if len(alphabet) not in (64, 65):
        raise ValueError("Base64 alphabet must contain 64 symbols and optional padding")
    text = to_text(value).strip()
    if remove_non_alphabet:
        text = _outside(alphabet).sub("", text)
    source = alphabet + ("=" if len(alphabet) == 64 else "")
    text = _translate(text, source, _BASE64)
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text, validate=strict)


@implementation("To Base32", category="Encoding")
def to_base32(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, "A-Z2-7=")))
    if len(alphabet) not in (32, 33):
        raise ValueError("Base32 alphabet must contain 32 symbols and optional padding")
    result = base64.b32encode(to_bytes(value)).decode("ascii")
    if len(alphabet) == 32:
        result = result.rstrip("=")
        return _translate(result, _BASE32[:32], alphabet)
    return _translate(result, _BASE32, alphabet)


@implementation("From Base32", category="Encoding")
def from_base32(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, "A-Z2-7=")))
    remove_non_alphabet = bool(arg(args, 1, True))
    if len(alphabet) not in (32, 33):
        raise ValueError("Base32 alphabet must contain 32 symbols and optional padding")
    text = to_text(value)
    if remove_non_alphabet:
        text = _outside(alphabet).sub("", text)
    source = alphabet + ("=" if len(alphabet) == 32 else "")
    text = _translate(text, source, _BASE32)
    text += "=" * (-len(text) % 8)
    return base64.b32decode(text, casefold=False)


@implementation("To Base85", category="Encoding")
def to_base85(value: Data, args: Args) -> str:
    alphabet_name = str(arg(args, 0, "!-u"))
    include_delimiter = bool(arg(args, 1, False))
    data = to_bytes(value)
    alphabet, standard = _base85_alphabet(alphabet_name)
    output: list[str] = []
    for index in range(0, len(data), 4):
        block = data[index : index + 4]
        number = int.from_bytes(block.ljust(4, b"\0"), "big")
        if standard and len(block) == 4 and number == 0:
            output.append("z")
            continue
        digits = [0] * 5
        for digit_index in range(4, -1, -1):
            number, digits[digit_index] = divmod(number, 85)
        output.append("".join(alphabet[digit] for digit in digits[: len(block) + 1]))
    result = "".join(output)
    return f"<~{result}~>" if include_delimiter and result else result


@implementation("From Base85", category="Encoding")
def from_base85(value: Data, args: Args) -> bytes:
    alphabet, _standard = _base85_alphabet(str(arg(args, 0, "!-u")))
    remove_non_alphabet = bool(arg(args, 1, True))
    zero_character = str(arg(args, 2, "z"))[:1]
    if zero_character and zero_character in alphabet:
        raise ValueError("all-zero group character cannot appear in the Base85 alphabet")
    text = to_text(value).strip()
    if text.startswith("<~") and text.endswith("~>"):
        text = text[2:-2]
    if remove_non_alphabet:
        text = _outside(alphabet + zero_character + "~").sub("", text)
        if text.startswith("<~") and text.endswith("~>"):
            text = text[2:-2]
    if not text:
        return b""
    indexes = {character: index for index, character in enumerate(alphabet)}
    output = bytearray()
    position = 0
    while position < len(text):
        if zero_character and text[position] == zero_character:
            output.extend(b"\0" * 4)
            position += 1
            continue
        group = text[position : position + 5]
        if len(group) == 1:
            raise ValueError("incomplete Base85 group")
        try:
            digits = [indexes[character] for character in group]
        except KeyError as exc:
            raise ValueError(f"invalid Base85 character: {exc.args[0]!r}") from exc
        number = 0
        for digit in [*digits, *([84] * (5 - len(digits)))]:
            number = number * 85 + digit
        if number > 0xFFFFFFFF:
            raise ValueError("invalid Base85 group")
        output.extend(number.to_bytes(4, "big")[: len(group) - 1])
        position += len(group)
    return bytes(output)


def _base85_alphabet(name: str) -> tuple[str, bool]:
    aliases = {
        "Standard": "!-u",
        "Ascii85": "!-u",
        "Z85": _Z85_SPEC,
        "Z85 (ZeroMQ)": _Z85_SPEC,
        "IPv6": _IPV6_BASE85_SPEC,
    }
    specification = aliases.get(name, name)
    alphabet = expand_alphabet(specification)
    if len(alphabet) != 85 or len(set(alphabet)) != 85:
        raise ValueError("Base85 alphabet must contain 85 unique symbols")
    return alphabet, specification == "!-u"


@implementation("To Base58", category="Encoding")
def to_base58(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, _BASE58)))
    return _base_n_encode(to_bytes(value), alphabet)


@implementation("From Base58", category="Encoding")
def from_base58(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, _BASE58)))
    remove_non_alphabet = bool(arg(args, 1, True))
    text = to_text(value)
    if remove_non_alphabet:
        text = "".join(character for character in text if character in alphabet)
    return _base_n_decode(text, alphabet)


@implementation("To Base62", category="Encoding")
def to_base62(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, "0-9A-Za-z")))
    return _base_n_encode(to_bytes(value), alphabet)


@implementation("From Base62", category="Encoding")
def from_base62(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, "0-9A-Za-z")))
    return _base_n_decode(to_text(value), alphabet)


@implementation("To Hex", category="Encoding")
def to_hex(value: Data, args: Args) -> str:
    delimiter_name = arg(args, 0, "Space")
    bytes_per_line = require_int(arg(args, 1, 0), name="bytes per line")
    data = to_bytes(value)
    if delimiter_name == "0x with comma":
        prefix, delimiter = "0x", ","
    elif delimiter_name in {"0x", "\\x"}:
        prefix, delimiter = str(delimiter_name), ""
    else:
        prefix, delimiter = "", char_rep(delimiter_name, " ")
    if not bytes_per_line or bytes_per_line < 1:
        return _hex_line(data, prefix, delimiter)
    return "\n".join(
        _hex_line(data[index : index + bytes_per_line], prefix, delimiter)
        for index in range(0, len(data), bytes_per_line)
    )


def _hex_line(data: bytes, prefix: str, delimiter: str) -> str:
    """Join the hex bytes of *data*; uses ``bytes.hex`` (C speed) for the common cases."""
    if not prefix:
        if not delimiter:
            return data.hex()
        if len(delimiter) == 1 and delimiter.isascii():
            return data.hex(delimiter)
    digits = data.hex()
    return delimiter.join(prefix + digits[index : index + 2] for index in range(0, len(digits), 2))


@implementation("From Hex", category="Encoding")
def from_hex(value: Data, args: Args) -> bytes:
    delimiter_name = str(arg(args, 0, "Auto"))
    text = to_text(value).strip()
    if not text:
        return b""
    if delimiter_name == "Auto":
        text = re.sub(r"(?:0x|\\x)", "", text, flags=re.IGNORECASE)
        digits = _NON_HEX.sub("", text)
    else:
        delimiter = char_rep(delimiter_name, " ")
        if delimiter_name == "0x with comma":
            text = text.replace("0x", "").replace("0X", "").replace(",", "")
        elif delimiter_name in {"0x", "\\x"}:
            text = text.replace(delimiter_name, "")
        elif delimiter:
            text = text.replace(delimiter, "")
        digits = text
    if len(digits) % 2:
        digits = "0" + digits
    return bytes.fromhex(digits)


def _numeric_delimiter(name: object, default: str = " ") -> str:
    return char_rep(name, default)


def _format_numbers(data: bytes, base: int, delimiter: str, width: int) -> str:
    formatter = {2: "b", 8: "o", 10: "d", 16: "x"}[base]
    return delimiter.join(format(byte, f"0{width}{formatter}") for byte in data)


def _parse_numbers(text: str, base: int, delimiter: str, width: int) -> bytes:
    if not text:
        return b""
    if delimiter:
        tokens = [token for token in text.split(delimiter) if token]
    else:
        compact = re.sub(r"\s+", "", text)
        tokens = [compact[index : index + width] for index in range(0, len(compact), width)]
    return bytes(int(token.strip(), base) & 0xFF for token in tokens)


@implementation("To Binary", category="Encoding")
def to_binary(value: Data, args: Args) -> str:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    width = require_int(arg(args, 1, 8)) or 8
    return _format_numbers(to_bytes(value), 2, delimiter, width)


@implementation("From Binary", category="Encoding")
def from_binary(value: Data, args: Args) -> bytes:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    width = require_int(arg(args, 1, 8)) or 8
    return _parse_numbers(to_text(value), 2, delimiter, width)


@implementation("To Octal", category="Encoding")
def to_octal(value: Data, args: Args) -> str:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _format_numbers(to_bytes(value), 8, delimiter, 3)


@implementation("From Octal", category="Encoding")
def from_octal(value: Data, args: Args) -> bytes:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _parse_numbers(to_text(value), 8, delimiter, 3)


@implementation("To Decimal", category="Encoding")
def to_decimal(value: Data, args: Args) -> str:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _format_numbers(to_bytes(value), 10, delimiter, 1)


@implementation("From Decimal", category="Encoding")
def from_decimal(value: Data, args: Args) -> bytes:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _parse_numbers(to_text(value), 10, delimiter, 3)


@implementation("To Charcode", category="Encoding")
def to_charcode(value: Data, args: Args) -> str:
    delimiter = char_rep(arg(args, 0, "Space"), " ")
    base = require_int(arg(args, 1, 16), name="base")
    text = to_text(value)
    if not 2 <= base <= 36:
        raise ValueError("base must be between 2 and 36")
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"

    def encode(number: int) -> str:
        if number == 0:
            return "0"
        result = ""
        while number:
            number, remainder = divmod(number, base)
            result = digits[remainder] + result
        return result

    def encode_character(character: str) -> str:
        ordinal = ord(character)
        encoded = encode(ordinal)
        if base != 16:
            return encoded
        width = 2 if ordinal < 256 else 4 if ordinal < 65536 else 6 if ordinal < 16777216 else 8
        return encoded.zfill(width)

    return delimiter.join(encode_character(character) for character in text)


@implementation("From Charcode", category="Encoding")
def from_charcode(value: Data, args: Args) -> bytes:
    delimiter = char_rep(arg(args, 0, "Space"), " ")
    base = require_int(arg(args, 1, 16), name="base")
    if not 2 <= base <= 36:
        raise ValueError("base must be between 2 and 36")
    text = to_text(value)
    if not text:
        return b""
    tokens = text.split(delimiter) if delimiter else [text]
    if len(tokens) == 1 and len(text) > 17:
        tokens = [text[index : index + 2] for index in range(0, len(text), 2)]
    return "".join(chr(int(token, base)) for token in tokens if token).encode("utf-8")


@implementation("URL Encode", category="Encoding")
def url_encode(value: Data, args: Args) -> str:
    encode_all = bool(arg(args, 0, False))
    uppercase = bool(arg(args, 1, False))
    safe = "" if encode_all else "~()*!.'-_"
    result = quote(to_text(value), safe=safe)
    return (
        re.sub(r"%[0-9a-fA-F]{2}", lambda match: match.group(0).upper(), result)
        if uppercase
        else result
    )


@implementation("URL Decode", category="Encoding")
def url_decode(value: Data, args: Args) -> str:
    convert_plus = bool(arg(args, 0, True))
    text = to_text(value)
    return unquote_plus(text) if convert_plus else unquote(text)


@implementation("To HTML Entity", category="Encoding")
def to_html_entity(value: Data, args: Args) -> str:
    convert_all = bool(arg(args, 0, False))
    mode = str(arg(args, 1, "Named entities"))
    if mode not in {"Named entities", "Numeric entities", "Hex entities"}:
        raise ValueError("entity mode must be Named entities, Numeric entities, or Hex entities")
    output: list[str] = []
    for character in to_text(value):
        ordinal = ord(character)
        name = _HTML_ENTITY_NAMES.get(character)
        if mode == "Numeric entities" and (convert_all or ordinal > 255 or name):
            output.append(f"&#{ordinal};")
        elif mode == "Hex entities" and (convert_all or ordinal > 255 or name):
            output.append(f"&#x{ordinal:x};")
        elif mode == "Named entities" and name:
            output.append(f"&{name};")
        elif mode == "Named entities" and (convert_all or ordinal > 255):
            output.append(f"&#{ordinal};")
        else:
            output.append(character)
    return "".join(output)


@implementation("From HTML Entity", category="Encoding")
def from_html_entity(value: Data, _args: Args) -> str:
    def decode(match: re.Match[str]) -> str:
        entity = match.group(1)
        if entity.startswith("#x") or entity.startswith("#X"):
            digits, base = entity[2:], 16
        elif entity.startswith("#"):
            digits, base = entity[1:], 10
        else:
            return html.entities.html5.get(entity + ";", match.group(0))
        try:
            ordinal = int(digits, base)
            return chr(ordinal) if 0 <= ordinal <= 0x10FFFF else match.group(0)
        except (ValueError, OverflowError):
            return match.group(0)

    return re.sub(r"&(#?x?[A-Za-z0-9]{1,20});", decode, to_text(value))


@implementation("To Quoted Printable", category="Encoding")
def to_quoted_printable(value: Data, _args: Args) -> str:
    return quopri.encodestring(to_bytes(value)).decode("ascii")


@implementation("From Quoted Printable", category="Encoding")
def from_quoted_printable(value: Data, _args: Args) -> bytes:
    return quopri.decodestring(to_bytes(value))


@implementation("To Punycode", category="Encoding")
def to_punycode(value: Data, args: Args) -> str:
    text = to_text(value)
    codec = "idna" if bool(arg(args, 0, False)) else "punycode"
    return text.encode(codec).decode("ascii")


@implementation("From Punycode", category="Encoding")
def from_punycode(value: Data, args: Args) -> str:
    text = to_text(value)
    codec = "idna" if bool(arg(args, 0, False)) else "punycode"
    return text.encode("ascii").decode(codec)


@implementation("To Modhex", category="Encoding")
def to_modhex(value: Data, _args: Args) -> str:
    return to_bytes(value).hex().translate(str.maketrans("0123456789abcdef", _MODHEX))


@implementation("From Modhex", category="Encoding")
def from_modhex(value: Data, _args: Args) -> bytes:
    translated = to_text(value).translate(str.maketrans(_MODHEX, "0123456789abcdef"))
    return bytes.fromhex(translated)


@implementation("To Float", category="Encoding")
def to_float(value: Data, args: Args) -> str:
    endian = str(arg(args, 0, "Big Endian"))
    precision = str(arg(args, 1, "Float (4 bytes)"))
    delimiter = char_rep(arg(args, 2, "Space"), " ")
    code = "d" if precision.startswith("Double") else "f"
    size = struct.calcsize(code)
    prefix = ">" if endian.startswith("Big") else "<"
    data = to_bytes(value)
    if len(data) % size:
        raise ValueError(f"input is not a multiple of {size} bytes")
    return delimiter.join(
        str(struct.unpack(prefix + code, data[index : index + size])[0])
        for index in range(0, len(data), size)
    )


@implementation("From Float", category="Encoding")
def from_float(value: Data, args: Args) -> bytes:
    endian = str(arg(args, 0, "Big Endian"))
    precision = str(arg(args, 1, "Float (4 bytes)"))
    delimiter = char_rep(arg(args, 2, "Space"), " ")
    code = "d" if precision.startswith("Double") else "f"
    prefix = ">" if endian.startswith("Big") else "<"
    text = to_text(value)
    if not text:
        return b""
    tokens = text.split(delimiter) if delimiter else [text]
    return b"".join(struct.pack(prefix + code, float(token)) for token in tokens)


@implementation("To Base", category="Encoding")
def to_base(value: Data, args: Args) -> str:
    radix = require_int(arg(args, 0, 36), name="radix")
    if not 2 <= radix <= 36:
        raise ValueError("radix must be between 2 and 36")
    try:
        number = Fraction(Decimal(to_text(value).strip()))
    except (InvalidOperation, ValueError, ZeroDivisionError) as exc:
        raise ValueError("input must be a decimal number") from exc
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    number = abs(number)
    integer, remainder = divmod(number.numerator, number.denominator)
    output: list[str] = []
    while integer:
        integer, digit = divmod(integer, radix)
        output.append(alphabet[digit])
    result = "".join(reversed(output)) or "0"
    fraction: list[str] = []
    while remainder and len(fraction) < 50:
        remainder *= radix
        digit, remainder = divmod(remainder, number.denominator)
        fraction.append(alphabet[digit])
    return sign + result + ("." + "".join(fraction) if fraction else "")


@implementation("From Base", category="Encoding")
def from_base(value: Data, args: Args) -> str:
    radix = require_int(arg(args, 0, 36), name="radix")
    if not 2 <= radix <= 36:
        raise ValueError("radix must be between 2 and 36")
    text = re.sub(r"\s+", "", to_text(value)).lower()
    sign = -1 if text.startswith("-") else 1
    if text[:1] in {"-", "+"}:
        text = text[1:]
    if text.count(".") > 1 or not text:
        raise ValueError("input must be a number in the selected radix")
    integer_text, _, fraction_text = text.partition(".")
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    values = {character: index for index, character in enumerate(alphabet[:radix])}
    try:
        integer = 0
        for character in integer_text or "0":
            integer = integer * radix + values[character]
        fraction = sum(
            Fraction(values[character], radix**position)
            for position, character in enumerate(fraction_text, start=1)
        )
    except KeyError as exc:
        raise ValueError(f"digit {exc.args[0]!r} is not valid in base {radix}") from exc
    number = sign * (Fraction(integer) + fraction)
    if number.denominator == 1:
        return str(number.numerator)
    with localcontext() as context:
        context.prec = 50
        rendered = format(Decimal(number.numerator) / Decimal(number.denominator), "f")
    return rendered.rstrip("0").rstrip(".")


@implementation("To Hex Content", category="Encoding")
def to_hex_content(value: Data, _args: Args) -> str:
    return to_bytes(value).hex()


@implementation("From Hex Content", category="Encoding")
def from_hex_content(value: Data, _args: Args) -> bytes:
    return binascii.unhexlify(re.sub(r"\s+", "", to_text(value)))
