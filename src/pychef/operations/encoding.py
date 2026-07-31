"""Binary-to-text encodings and character representation operations.

Portions are behavior-compatible rewrites of CyberChef operations, Crown
Copyright 2016, Apache-2.0. Modified and rewritten in Python for PyChef.
"""

from __future__ import annotations

import base64
import binascii
import html
import quopri
import re
import struct
from urllib.parse import quote, unquote, unquote_plus

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, expand_alphabet, require_int

_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MODHEX = "cbdefghijklnrtuv"
_HEX = re.compile(r"[0-9a-fA-F]")


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


@operation("To Base64", category="Encoding")
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


@operation("From Base64", category="Encoding")
def from_base64(value: Data, args: Args) -> bytes:
    alphabet_spec = str(arg(args, 0, "A-Za-z0-9+/="))
    remove_non_alphabet = bool(arg(args, 1, True))
    strict = bool(arg(args, 2, False))
    alphabet = expand_alphabet(alphabet_spec)
    if len(alphabet) not in (64, 65):
        raise ValueError("Base64 alphabet must contain 64 symbols and optional padding")
    text = to_text(value).strip()
    if remove_non_alphabet:
        allowed = set(alphabet)
        text = "".join(character for character in text if character in allowed)
    source = alphabet + ("=" if len(alphabet) == 64 else "")
    text = _translate(text, source, _BASE64)
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text, validate=strict)


@operation("To Base32", category="Encoding")
def to_base32(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, "A-Z2-7=")))
    if len(alphabet) not in (32, 33):
        raise ValueError("Base32 alphabet must contain 32 symbols and optional padding")
    result = base64.b32encode(to_bytes(value)).decode("ascii")
    if len(alphabet) == 32:
        result = result.rstrip("=")
        return _translate(result, _BASE32[:32], alphabet)
    return _translate(result, _BASE32, alphabet)


@operation("From Base32", category="Encoding")
def from_base32(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, "A-Z2-7=")))
    remove_non_alphabet = bool(arg(args, 1, True))
    if len(alphabet) not in (32, 33):
        raise ValueError("Base32 alphabet must contain 32 symbols and optional padding")
    text = to_text(value)
    if remove_non_alphabet:
        allowed = set(alphabet)
        text = "".join(character for character in text if character in allowed)
    source = alphabet + ("=" if len(alphabet) == 32 else "")
    text = _translate(text, source, _BASE32)
    text += "=" * (-len(text) % 8)
    return base64.b32decode(text, casefold=False)


@operation("To Base85", category="Encoding")
def to_base85(value: Data, args: Args) -> str:
    alphabet = str(arg(args, 0, "Standard"))
    include_delimiter = bool(arg(args, 1, False))
    data = to_bytes(value)
    if alphabet in {"Standard", "!-u", "Ascii85"}:
        return base64.a85encode(data, adobe=include_delimiter).decode("ascii")
    if alphabet in {"Z85", "0-9a-zA-Z.-:+=^!/*?&<>()[]{}@%$#"}:
        return base64.b85encode(data).decode("ascii")
    custom = expand_alphabet(alphabet)
    if len(custom) != 85:
        raise ValueError("Base85 alphabet must contain 85 symbols")
    standard = base64.a85encode(data).decode("ascii")
    return _translate(standard, "".join(chr(code) for code in range(33, 118)), custom)


@operation("From Base85", category="Encoding")
def from_base85(value: Data, args: Args) -> bytes:
    alphabet = str(arg(args, 0, "Standard"))
    text = to_text(value).strip()
    if alphabet in {"Standard", "!-u", "Ascii85"}:
        return base64.a85decode(text, adobe=text.startswith("<~"))
    if alphabet in {"Z85", "0-9a-zA-Z.-:+=^!/*?&<>()[]{}@%$#"}:
        return base64.b85decode(text)
    custom = expand_alphabet(alphabet)
    if len(custom) != 85:
        raise ValueError("Base85 alphabet must contain 85 symbols")
    standard = "".join(chr(code) for code in range(33, 118))
    return base64.a85decode(_translate(text, custom, standard))


@operation("To Base58", category="Encoding")
def to_base58(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, _BASE58)))
    return _base_n_encode(to_bytes(value), alphabet)


@operation("From Base58", category="Encoding")
def from_base58(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, _BASE58)))
    remove_non_alphabet = bool(arg(args, 1, True))
    text = to_text(value)
    if remove_non_alphabet:
        text = "".join(character for character in text if character in alphabet)
    return _base_n_decode(text, alphabet)


@operation("To Base62", category="Encoding")
def to_base62(value: Data, args: Args) -> str:
    alphabet = expand_alphabet(str(arg(args, 0, "0-9A-Za-z")))
    return _base_n_encode(to_bytes(value), alphabet)


@operation("From Base62", category="Encoding")
def from_base62(value: Data, args: Args) -> bytes:
    alphabet = expand_alphabet(str(arg(args, 0, "0-9A-Za-z")))
    return _base_n_decode(to_text(value), alphabet)


@operation("To Hex", category="Encoding")
def to_hex(value: Data, args: Args) -> str:
    delimiter_name = arg(args, 0, "Space")
    bytes_per_line = require_int(arg(args, 1, 0), name="bytes per line")
    data = to_bytes(value)
    if delimiter_name == "0x with comma":
        chunks = [f"0x{byte:02x}" for byte in data]
        delimiter = ","
    elif delimiter_name in {"0x", "\\x"}:
        chunks = [f"{delimiter_name}{byte:02x}" for byte in data]
        delimiter = ""
    else:
        chunks = [f"{byte:02x}" for byte in data]
        delimiter = char_rep(delimiter_name, " ")
    if not bytes_per_line or bytes_per_line < 1:
        return delimiter.join(chunks)
    lines = [
        delimiter.join(chunks[index : index + bytes_per_line])
        for index in range(0, len(chunks), bytes_per_line)
    ]
    return "\n".join(lines)


@operation("From Hex", category="Encoding")
def from_hex(value: Data, args: Args) -> bytes:
    delimiter_name = str(arg(args, 0, "Auto"))
    text = to_text(value).strip()
    if not text:
        return b""
    if delimiter_name == "Auto":
        text = re.sub(r"(?:0x|\\x)", "", text, flags=re.IGNORECASE)
        digits = "".join(_HEX.findall(text))
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


@operation("To Binary", category="Encoding")
def to_binary(value: Data, args: Args) -> str:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    width = require_int(arg(args, 1, 8)) or 8
    return _format_numbers(to_bytes(value), 2, delimiter, width)


@operation("From Binary", category="Encoding")
def from_binary(value: Data, args: Args) -> bytes:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    width = require_int(arg(args, 1, 8)) or 8
    return _parse_numbers(to_text(value), 2, delimiter, width)


@operation("To Octal", category="Encoding")
def to_octal(value: Data, args: Args) -> str:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _format_numbers(to_bytes(value), 8, delimiter, 3)


@operation("From Octal", category="Encoding")
def from_octal(value: Data, args: Args) -> bytes:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _parse_numbers(to_text(value), 8, delimiter, 3)


@operation("To Decimal", category="Encoding")
def to_decimal(value: Data, args: Args) -> str:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _format_numbers(to_bytes(value), 10, delimiter, 1)


@operation("From Decimal", category="Encoding")
def from_decimal(value: Data, args: Args) -> bytes:
    delimiter = _numeric_delimiter(arg(args, 0, "Space"))
    return _parse_numbers(to_text(value), 10, delimiter, 3)


@operation("To Charcode", category="Encoding")
def to_charcode(value: Data, args: Args) -> str:
    base = require_int(arg(args, 0, 10), name="base")
    delimiter = char_rep(arg(args, 1, "Space"), " ")
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

    return delimiter.join(encode(ord(character)) for character in text)


@operation("From Charcode", category="Encoding")
def from_charcode(value: Data, args: Args) -> str:
    base = require_int(arg(args, 0, 10), name="base")
    delimiter = char_rep(arg(args, 1, "Space"), " ")
    text = to_text(value)
    tokens = text.split(delimiter) if delimiter else re.findall(r"[0-9A-Za-z]+", text)
    return "".join(chr(int(token, base)) for token in tokens if token)


@operation("URL Encode", category="Encoding")
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


@operation("URL Decode", category="Encoding")
def url_decode(value: Data, args: Args) -> str:
    convert_plus = bool(arg(args, 0, True))
    text = to_text(value)
    return unquote_plus(text) if convert_plus else unquote(text)


@operation("To HTML Entity", category="Encoding")
def to_html_entity(value: Data, args: Args) -> str:
    named = bool(arg(args, 0, True))
    text = to_text(value)
    if named:
        return html.escape(text, quote=True).replace("'", "&#x27;")
    return "".join(
        f"&#{ord(character)};" if ord(character) > 127 or character in "&<>\"'" else character
        for character in text
    )


@operation("From HTML Entity", category="Encoding")
def from_html_entity(value: Data, _args: Args) -> str:
    return html.unescape(to_text(value))


@operation("To Quoted Printable", category="Encoding")
def to_quoted_printable(value: Data, _args: Args) -> str:
    return quopri.encodestring(to_bytes(value)).decode("ascii")


@operation("From Quoted Printable", category="Encoding")
def from_quoted_printable(value: Data, _args: Args) -> bytes:
    return quopri.decodestring(to_bytes(value))


@operation("To Punycode", category="Encoding")
def to_punycode(value: Data, _args: Args) -> str:
    return to_text(value).encode("idna").decode("ascii")


@operation("From Punycode", category="Encoding")
def from_punycode(value: Data, _args: Args) -> str:
    return to_text(value).encode("ascii").decode("idna")


@operation("To Modhex", category="Encoding")
def to_modhex(value: Data, _args: Args) -> str:
    return to_bytes(value).hex().translate(str.maketrans("0123456789abcdef", _MODHEX))


@operation("From Modhex", category="Encoding")
def from_modhex(value: Data, _args: Args) -> bytes:
    translated = to_text(value).translate(str.maketrans(_MODHEX, "0123456789abcdef"))
    return bytes.fromhex(translated)


@operation("To Float", category="Encoding")
def to_float(value: Data, args: Args) -> str:
    endian = str(arg(args, 0, "Big endian"))
    precision = str(arg(args, 1, "Single precision"))
    code = "f" if precision.startswith("Single") else "d"
    size = struct.calcsize(code)
    prefix = ">" if endian.startswith("Big") else "<"
    data = to_bytes(value)
    return " ".join(
        str(struct.unpack(prefix + code, data[index : index + size])[0])
        for index in range(0, len(data), size)
        if len(data[index : index + size]) == size
    )


@operation("From Float", category="Encoding")
def from_float(value: Data, args: Args) -> bytes:
    endian = str(arg(args, 0, "Big endian"))
    precision = str(arg(args, 1, "Single precision"))
    code = "f" if precision.startswith("Single") else "d"
    prefix = ">" if endian.startswith("Big") else "<"
    tokens = re.findall(
        r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?|[-+]?inf|nan", to_text(value), re.I
    )
    return b"".join(struct.pack(prefix + code, float(token)) for token in tokens)


@operation("To Base", category="Encoding")
def to_base(value: Data, args: Args) -> str:
    radix = require_int(arg(args, 0, 16), name="radix")
    if not 2 <= radix <= 36:
        raise ValueError("radix must be between 2 and 36")
    number = int.from_bytes(to_bytes(value), "big")
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if number == 0:
        return "0"
    output = ""
    while number:
        number, remainder = divmod(number, radix)
        output = alphabet[remainder] + output
    return output


@operation("From Base", category="Encoding")
def from_base(value: Data, args: Args) -> bytes:
    radix = require_int(arg(args, 0, 16), name="radix")
    number = int(to_text(value).strip(), radix)
    size = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(size, "big")


@operation("To Hex Content", category="Encoding")
def to_hex_content(value: Data, _args: Args) -> str:
    return to_bytes(value).hex()


@operation("From Hex Content", category="Encoding")
def from_hex_content(value: Data, _args: Args) -> bytes:
    return binascii.unhexlify(re.sub(r"\s+", "", to_text(value)))
