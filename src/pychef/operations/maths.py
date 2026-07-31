"""Arithmetic, bitwise, distance, and integer operations."""

from __future__ import annotations

import base64
import math
import statistics
from collections.abc import Callable
from decimal import Decimal, InvalidOperation, getcontext
from functools import reduce

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, require_int

getcontext().prec = 100


def _key_bytes(value: object) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        option = str(value.get("option", "Hex"))
    else:
        text, option = str(value or ""), "Hex"
    if not text:
        return b"\0"
    if option == "Hex":
        return bytes.fromhex(text)
    if option == "Decimal":
        return bytes(int(token) & 0xFF for token in text.replace(",", " ").split())
    if option == "Binary":
        return bytes(int(token, 2) & 0xFF for token in text.replace(",", " ").split())
    if option == "Base64":
        return base64.b64decode(text)
    if option == "Latin1":
        return text.encode("latin-1")
    return text.encode()


def _bitwise(
    value: Data,
    args: Args,
    function: Callable[[int, int], int],
    *,
    xor: bool = False,
) -> bytes:
    key = bytearray(_key_bytes(arg(args, 0, {"string": "", "option": "Hex"})))
    scheme = str(arg(args, 1, "Standard")) if xor else "Standard"
    null_preserving = bool(arg(args, 2, False)) if xor else False
    output = bytearray()
    data = to_bytes(value)
    for index, byte in enumerate(data):
        key_byte = (
            data[index + 1]
            if scheme == "Cascade" and index + 1 < len(data)
            else key[index % len(key)]
        )
        result = byte if null_preserving and byte in {0, key_byte} else function(byte, key_byte)
        output.append(result & 0xFF)
        if scheme == "Input differential" and not (null_preserving and byte in {0, key_byte}):
            key[index % len(key)] = byte
        elif scheme == "Output differential" and not (null_preserving and byte in {0, key_byte}):
            key[index % len(key)] = result
    return bytes(output)


@operation("XOR", category="Bitwise")
def xor(value: Data, args: Args) -> bytes:
    return _bitwise(value, args, lambda left, right: left ^ right, xor=True)


@operation("AND", category="Bitwise")
def bitwise_and(value: Data, args: Args) -> bytes:
    return _bitwise(value, args, lambda left, right: left & right)


@operation("OR", category="Bitwise")
def bitwise_or(value: Data, args: Args) -> bytes:
    return _bitwise(value, args, lambda left, right: left | right)


@operation("ADD", category="Bitwise")
def add_bytes(value: Data, args: Args) -> bytes:
    return _bitwise(value, args, lambda left, right: (left + right) % 256)


@operation("SUB", category="Bitwise")
def subtract_bytes(value: Data, args: Args) -> bytes:
    return _bitwise(value, args, lambda left, right: (left - right) % 256)


@operation("NOT", category="Bitwise")
def bitwise_not(value: Data, _args: Args) -> bytes:
    return bytes((~byte) & 0xFF for byte in to_bytes(value))


@operation("Bit shift left", category="Bitwise")
def bit_shift_left(value: Data, args: Args) -> bytes:
    amount = require_int(arg(args, 0, 1))
    return bytes((byte << amount) & 0xFF for byte in to_bytes(value))


@operation("Bit shift right", category="Bitwise")
def bit_shift_right(value: Data, args: Args) -> bytes:
    amount = require_int(arg(args, 0, 1))
    arithmetic = str(arg(args, 1, "Logical shift")) == "Arithmetic shift"
    return bytes(
        ((byte >> amount) ^ (byte & 0x80 if arithmetic else 0)) & 0xFF for byte in to_bytes(value)
    )


def _rotate_byte(byte: int, amount: int, left: bool) -> int:
    amount %= 8
    if not amount:
        return byte
    if left:
        return ((byte << amount) | (byte >> (8 - amount))) & 0xFF
    return ((byte >> amount) | (byte << (8 - amount))) & 0xFF


def _rotate(value: Data, args: Args, left: bool) -> bytes:
    amount = require_int(arg(args, 0, 1))
    data = to_bytes(value)
    if not bool(arg(args, 1, False)):
        return bytes(_rotate_byte(byte, amount, left) for byte in data)
    if not data:
        return b""
    width = len(data) * 8
    number = int.from_bytes(data, "big")
    amount %= width
    mask = (1 << width) - 1
    if left:
        number = ((number << amount) | (number >> (width - amount))) & mask
    else:
        number = ((number >> amount) | (number << (width - amount))) & mask
    return number.to_bytes(len(data), "big")


@operation("Rotate left", category="Bitwise")
def rotate_left(value: Data, args: Args) -> bytes:
    return _rotate(value, args, True)


@operation("Rotate right", category="Bitwise")
def rotate_right(value: Data, args: Args) -> bytes:
    return _rotate(value, args, False)


@operation("ROR13", category="Hashing")
def ror13(value: Data, _args: Args) -> str:
    result = 0
    for byte in to_bytes(value):
        result = ((result >> 13) | (result << 19)) & 0xFFFFFFFF
        result = (result + byte) & 0xFFFFFFFF
    return f"0x{result:08X}"


def _numbers(value: Data, delimiter_name: object) -> list[Decimal]:
    delimiter = char_rep(delimiter_name, " ")
    tokens = to_text(value).split(delimiter) if delimiter else to_text(value).split()
    numbers: list[Decimal] = []
    for token in tokens:
        try:
            numbers.append(Decimal(token.strip()))
        except InvalidOperation:
            continue
    if not numbers:
        raise ValueError("input contains no numbers")
    return numbers


def _decimal_text(number: Decimal) -> str:
    if number.is_nan() or number.is_infinite():
        return str(number)
    formatted = format(number, "f")
    if "." in formatted:
        formatted = formatted.rstrip("0").rstrip(".")
    return formatted or "0"


def _reduce_numbers(
    value: Data, args: Args, function: Callable[[Decimal, Decimal], Decimal]
) -> str:
    numbers = _numbers(value, arg(args, 0, "Space"))
    return _decimal_text(reduce(function, numbers))


@operation("Sum", category="Arithmetic")
def sum_numbers(value: Data, args: Args) -> str:
    return _decimal_text(sum(_numbers(value, arg(args, 0, "Space")), Decimal(0)))


@operation("Subtract", category="Arithmetic")
def subtract_numbers(value: Data, args: Args) -> str:
    return _reduce_numbers(value, args, lambda left, right: left - right)


@operation("Multiply", category="Arithmetic")
def multiply_numbers(value: Data, args: Args) -> str:
    return _reduce_numbers(value, args, lambda left, right: left * right)


@operation("Divide", category="Arithmetic")
def divide_numbers(value: Data, args: Args) -> str:
    return _reduce_numbers(value, args, lambda left, right: left / right)


@operation("Mean", category="Arithmetic")
def mean(value: Data, args: Args) -> str:
    numbers = _numbers(value, arg(args, 0, "Space"))
    return _decimal_text(sum(numbers, Decimal(0)) / len(numbers))


@operation("Median", category="Arithmetic")
def median(value: Data, args: Args) -> str:
    return _decimal_text(Decimal(statistics.median(_numbers(value, arg(args, 0, "Space")))))


@operation("Standard Deviation", category="Arithmetic")
def standard_deviation(value: Data, args: Args) -> str:
    numbers = _numbers(value, arg(args, 0, "Space"))
    average = sum(numbers, Decimal(0)) / len(numbers)
    variance = sum(((number - average) ** 2 for number in numbers), Decimal(0)) / len(numbers)
    return _decimal_text(variance.sqrt())


@operation("MOD", category="Arithmetic")
def modulus(value: Data, args: Args) -> str:
    divisor = Decimal(str(arg(args, 0, 2)))
    if not divisor:
        raise ValueError("modulus cannot be zero")
    return " ".join(
        _decimal_text(number % divisor) for number in _numbers(value, arg(args, 1, "Space"))
    )


def _egcd(left: int, right: int) -> tuple[int, int, int]:
    old_r, remainder = left, right
    old_s, coefficient_s = 1, 0
    old_t, coefficient_t = 0, 1
    while remainder:
        quotient = old_r // remainder
        old_r, remainder = remainder, old_r - quotient * remainder
        old_s, coefficient_s = coefficient_s, old_s - quotient * coefficient_s
        old_t, coefficient_t = coefficient_t, old_t - quotient * coefficient_t
    return old_r, old_s, old_t


@operation("Extended GCD", category="Arithmetic")
def extended_gcd(value: Data, args: Args) -> str:
    left_arg, right_arg = str(arg(args, 0, "")).strip(), str(arg(args, 1, "")).strip()
    input_value = to_text(value).strip()
    if left_arg and right_arg:
        left, right = int(left_arg, 0), int(right_arg, 0)
    elif right_arg and input_value:
        left, right = int(input_value, 0), int(right_arg, 0)
    elif left_arg and input_value:
        left, right = int(left_arg, 0), int(input_value, 0)
    else:
        raise ValueError("values a and b must be defined")
    divisor, x, y = _egcd(left, right)
    return f"gcd: {abs(divisor)}\n\nBezout coefficients:\nx = {x}\ny = {y}\n\n"


@operation("Modular Exponentiation", category="Arithmetic")
def modular_exponentiation(value: Data, args: Args) -> str:
    base_arg = str(arg(args, 0, "")).strip()
    modulus_arg = str(arg(args, 1, "1")).strip()
    exponent_arg = str(arg(args, 2, "")).strip()
    input_value = to_text(value).strip()
    if base_arg and exponent_arg:
        base, exponent = base_arg, exponent_arg
    elif exponent_arg and input_value:
        base, exponent = input_value, exponent_arg
    elif base_arg and input_value:
        base, exponent = base_arg, input_value
    else:
        raise ValueError("base and exponent must be defined unambiguously")
    return str(pow(int(base, 0), int(exponent, 0), int(modulus_arg, 0)))


@operation("Modular Inverse", category="Arithmetic")
def modular_inverse(value: Data, args: Args) -> str:
    number_arg = str(arg(args, 0, "")).strip()
    modulus_arg = str(arg(args, 1, "")).strip()
    input_value = to_text(value).strip()
    if number_arg and modulus_arg:
        number, modulus_value = number_arg, modulus_arg
    elif modulus_arg and input_value:
        number, modulus_value = input_value, modulus_arg
    elif number_arg and input_value:
        number, modulus_value = number_arg, input_value
    else:
        raise ValueError("value and modulus must be defined")
    return str(pow(int(number, 0), -1, int(modulus_value, 0)))


@operation("Text-Integer Conversion", category="Arithmetic")
def text_integer_conversion(value: Data, args: Args) -> str:
    output_format = str(arg(args, 0, "String"))
    text = to_text(value).strip()
    if not text:
        number = 0
    elif text.lower().startswith("0x") or text.lstrip("+-").isdigit():
        number = int(text, 0)
    else:
        unquoted = (
            text[1:-1] if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'" else text
        )
        number = int.from_bytes(unquoted.encode(), "big")
    if output_format == "Decimal":
        return str(number)
    if output_format == "Hexadecimal":
        return f"0x{number:x}"
    size = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(size, "big").decode("utf-8", "replace").lstrip("\0")


@operation("Levenshtein Distance", category="Arithmetic")
def levenshtein_distance(value: Data, args: Args) -> str:
    delimiter = str(arg(args, 0, "\n")).replace("\\n", "\n")
    insertion = require_int(arg(args, 1, 1))
    deletion = require_int(arg(args, 2, 1))
    substitution = require_int(arg(args, 3, 1))
    left, separator, right = to_text(value).partition(delimiter)
    if not separator:
        raise ValueError("input does not contain the sample delimiter")
    previous = [index * insertion for index in range(len(right) + 1)]
    for left_index, left_character in enumerate(left, 1):
        current = [left_index * deletion]
        for right_index, right_character in enumerate(right, 1):
            current.append(
                min(
                    current[-1] + insertion,
                    previous[right_index] + deletion,
                    previous[right_index - 1]
                    + (0 if left_character == right_character else substitution),
                )
            )
        previous = current
    return str(previous[-1])


@operation("Haversine distance", category="Arithmetic")
def haversine_distance(value: Data, _args: Args) -> str:
    coordinates = [float(part.strip()) for part in to_text(value).split(",")]
    if len(coordinates) != 4:
        raise ValueError("input must be lat1, lng1, lat2, lng2")
    latitude1, longitude1, latitude2, longitude2 = map(math.radians, coordinates)
    delta_latitude, delta_longitude = latitude2 - latitude1, longitude2 - longitude1
    haversine = (
        math.sin(delta_latitude / 2) ** 2
        + math.cos(latitude1) * math.cos(latitude2) * math.sin(delta_longitude / 2) ** 2
    )
    return str(6_371_000 * 2 * math.atan2(math.sqrt(haversine), math.sqrt(1 - haversine)))
