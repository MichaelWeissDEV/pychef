"""Unit conversion, brute-force, networking, and presentation helpers."""

from __future__ import annotations

import base64
import html
import ipaddress
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, expand_alphabet, require_int

_AREA_FACTORS = {
    "Square metre (sq m)": "1",
    "Square kilometre (sq km)": "1e6",
    "Centiare (ca)": "1",
    "Deciare (da)": "10",
    "Are (a)": "100",
    "Decare (daa)": "1e3",
    "Hectare (ha)": "1e4",
    "Square inch (sq in)": "0.00064516",
    "Square foot (sq ft)": "0.09290304",
    "Square yard (sq yd)": "0.83612736",
    "Square mile (sq mi)": "2589988.110336",
    "Perch (sq per)": "42.21",
    "Rood (ro)": "1011",
    "International acre (ac)": "4046.8564224",
    "US survey acre (ac)": "4046.87261",
    "US survey square mile (sq mi)": "2589998.470305239",
    "US survey township": "93239944.9309886",
    "Yoctobarn (yb)": "1e-52",
    "Zeptobarn (zb)": "1e-49",
    "Attobarn (ab)": "1e-46",
    "Femtobarn (fb)": "1e-43",
    "Picobarn (pb)": "1e-40",
    "Nanobarn (nb)": "1e-37",
    "Microbarn (μb)": "1e-34",
    "Millibarn (mb)": "1e-31",
    "Barn (b)": "1e-28",
    "Kilobarn (kb)": "1e-25",
    "Megabarn (Mb)": "1e-22",
    "Planck area": "2.6e-70",
    "Shed": "1e-52",
    "Outhouse": "1e-34",
    "Washington D.C.": "176119191.502848",
    "Isle of Wight": "380000000",
    "Wales": "20779000000",
    "Texas": "696241000000",
}

_DISTANCE_FACTORS = {
    "Nanometres (nm)": "1e-9",
    "Micrometres (µm)": "1e-6",
    "Millimetres (mm)": "1e-3",
    "Centimetres (cm)": "1e-2",
    "Metres (m)": "1",
    "Kilometers (km)": "1e3",
    "Thou (th)": "0.0000254",
    "Inches (in)": "0.0254",
    "Feet (ft)": "0.3048",
    "Yards (yd)": "0.9144",
    "Chains (ch)": "20.1168",
    "Furlongs (fur)": "201.168",
    "Miles (mi)": "1609.344",
    "Leagues (lea)": "4828.032",
    "Fathoms (ftm)": "1.853184",
    "Cables": "185.3184",
    "Nautical miles": "1853.184",
    "Cars (4m)": "4",
    "Buses (8.4m)": "8.4",
    "American football fields (91m)": "91",
    "Football pitches (105m)": "105",
    "Earth-to-Moons": "380000000",
    "Earth's equators": "40075016.686",
    "Astronomical units (au)": "149597870700",
    "Light-years (ly)": "9460730472580800",
    "Parsecs (pc)": "3.0856776e16",
}

_MASS_FACTORS = {
    "Yoctogram (yg)": "1e-24",
    "Zeptogram (zg)": "1e-21",
    "Attogram (ag)": "1e-18",
    "Femtogram (fg)": "1e-15",
    "Picogram (pg)": "1e-12",
    "Nanogram (ng)": "1e-9",
    "Microgram (μg)": "1e-6",
    "Milligram (mg)": "1e-3",
    "Centigram (cg)": "1e-2",
    "Decigram (dg)": "1e-1",
    "Gram (g)": "1",
    "Decagram (dag)": "10",
    "Hectogram (hg)": "100",
    "Kilogram (kg)": "1000",
    "Megagram (Mg)": "1e6",
    "Tonne (t)": "1e6",
    "Gigagram (Gg)": "1e9",
    "Teragram (Tg)": "1e12",
    "Petagram (Pg)": "1e15",
    "Exagram (Eg)": "1e18",
    "Zettagram (Zg)": "1e21",
    "Yottagram (Yg)": "1e24",
    "Grain (gr)": "0.06479891",
    "Dram (dr)": "1.7718451953125",
    "Ounce (oz)": "28.349523125",
    "Pound (lb)": "453.59237",
    "Nail": "3175.14659",
    "Stone (st)": "6350.29318",
    "Quarter (gr)": "12700.58636",
    "Tod": "12700.58636",
    "US hundredweight (cwt)": "45359.237",
    "Imperial hundredweight (cwt)": "50802.34544",
    "US ton (t)": "907184.74",
    "Imperial ton (t)": "1016046.9088",
    "Pennyweight (dwt)": "1.55517384",
    "Troy dram (dr t)": "3.8879346",
    "Troy ounce (oz t)": "31.1034768",
    "Troy pound (lb t)": "373.2417216",
    "Mark": "248.8278144",
}

_SPEED_FACTORS = {
    "Metres per second (m/s)": "1",
    "Kilometres per hour (km/h)": "0.2778",
    "Miles per hour (mph)": "0.44704",
    "Knots (kn)": "0.5144",
    "Human hair growth rate": "4.8e-9",
    "Bamboo growth rate": "1.4e-5",
    "World's fastest snail": "0.00275",
    "Usain Bolt's top speed": "12.42",
    "Jet airliner cruising speed": "250",
    "Concorde": "603",
    "SR-71 Blackbird": "981",
    "Space Shuttle": "1400",
    "International Space Station": "7700",
    "Sound in standard atmosphere": "340.3",
    "Sound in water": "1500",
    "Lunar escape velocity": "2375",
    "Earth escape velocity": "11200",
    "Earth's solar orbit": "29800",
    "Solar system's Milky Way orbit": "200000",
    "Milky Way relative to the cosmic microwave background": "552000",
    "Solar escape velocity": "617700",
    "Neutron star escape velocity (0.3c)": "100000000",
    "Light in a diamond (0.4136c)": "124000000",
    "Signal in an optical fibre (0.667c)": "200000000",
    "Light (c)": "299792458",
}

_DATA_FACTORS: dict[str, int] = {
    "Bits (b)": 1,
    "Nibbles": 4,
    "Octets": 8,
    "Bytes (B)": 8,
    "Decabits": 10,
    "Hectobits": 100,
}
for prefix, power in (
    ("Kibi", 1),
    ("Mebi", 2),
    ("Gibi", 3),
    ("Tebi", 4),
    ("Pebi", 5),
    ("Exbi", 6),
    ("Zebi", 7),
    ("Yobi", 8),
):
    short = {
        "Kibi": "Ki",
        "Mebi": "Mi",
        "Gibi": "Gi",
        "Tebi": "Ti",
        "Pebi": "Pi",
        "Exbi": "Ei",
        "Zebi": "Zi",
        "Yobi": "Yi",
    }[prefix]
    _DATA_FACTORS[f"{prefix}bits ({short}b)"] = 1024**power
    _DATA_FACTORS[f"{prefix}bytes ({short}B)"] = 8 * 1024**power
for prefix, power, symbol in (
    ("Kilo", 3, "K"),
    ("Mega", 6, "M"),
    ("Giga", 9, "G"),
    ("Tera", 12, "T"),
    ("Peta", 15, "P"),
    ("Exa", 18, "E"),
    ("Zetta", 21, "Z"),
    ("Yotta", 24, "Y"),
):
    _DATA_FACTORS[f"{prefix}bits ({symbol}b)"] = 10**power
    _DATA_FACTORS[f"{prefix}bytes ({symbol}B)"] = 8 * 10**power


def _convert_units(value: Data, args: Args, factors: Mapping[str, str | int]) -> str:
    source = str(arg(args, 0, next(iter(factors))))
    target = str(arg(args, 1, next(iter(factors))))
    try:
        result = (
            Decimal(to_text(value).strip()) * Decimal(factors[source]) / Decimal(factors[target])
        )
    except (InvalidOperation, KeyError, ZeroDivisionError) as exc:
        raise ValueError("invalid value or unit selection") from exc
    rendered = format(result, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


@operation("Convert area", category="Data format")
def convert_area(value: Data, args: Args) -> str:
    return _convert_units(value, args, _AREA_FACTORS)


@operation("Convert data units", category="Data format")
def convert_data_units(value: Data, args: Args) -> str:
    return _convert_units(value, args, _DATA_FACTORS)


@operation("Convert distance", category="Data format")
def convert_distance(value: Data, args: Args) -> str:
    return _convert_units(value, args, _DISTANCE_FACTORS)


@operation("Convert mass", category="Data format")
def convert_mass(value: Data, args: Args) -> str:
    return _convert_units(value, args, _MASS_FACTORS)


@operation("Convert speed", category="Data format")
def convert_speed(value: Data, args: Args) -> str:
    return _convert_units(value, args, _SPEED_FACTORS)


@operation("Convert Leet Speak", category="Text")
def convert_leet(value: Data, args: Args) -> str:
    direction = str(arg(args, 0, "To Leet Speak"))
    mapping = str.maketrans("aAeEiIoOsStT", "44 33 11 00 55 77".replace(" ", ""))
    if direction == "To Leet Speak":
        return to_text(value).translate(mapping)
    reverse = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"})
    return to_text(value).translate(reverse)


def _escape_whitespace(value: str) -> str:
    return (
        value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    )


@operation("ROT13 Brute Force", category="Ciphers")
def rot13_brute_force(value: Data, args: Args) -> str:
    rotate_lower = bool(arg(args, 0, True))
    rotate_upper = bool(arg(args, 1, True))
    rotate_numbers = bool(arg(args, 2, False))
    length = require_int(arg(args, 3, 100))
    offset = require_int(arg(args, 4, 0))
    print_amount = bool(arg(args, 5, True))
    crib = str(arg(args, 6, "")).casefold()
    sample = to_text(value)[offset : offset + length]
    lines: list[str] = []
    for amount in range(1, 26):
        output = ""
        for character in sample:
            if rotate_lower and "a" <= character <= "z":
                character = chr((ord(character) - 97 + amount) % 26 + 97)
            elif rotate_upper and "A" <= character <= "Z":
                character = chr((ord(character) - 65 + amount) % 26 + 65)
            elif rotate_numbers and "0" <= character <= "9":
                character = chr((ord(character) - 48 + amount) % 10 + 48)
            output += character
        if crib in output.casefold():
            prefix = f"Amount = {amount:2d}: " if print_amount else ""
            lines.append(prefix + _escape_whitespace(output))
    return "\n".join(lines)


@operation("ROT47 Brute Force", category="Ciphers")
def rot47_brute_force(value: Data, args: Args) -> str:
    length = require_int(arg(args, 0, 100))
    offset = require_int(arg(args, 1, 0))
    print_amount = bool(arg(args, 2, True))
    crib = str(arg(args, 3, "")).casefold()
    sample = to_text(value)[offset : offset + length]
    lines: list[str] = []
    for amount in range(1, 94):
        output = "".join(
            chr((ord(character) - 33 + amount) % 94 + 33)
            if 33 <= ord(character) <= 126
            else character
            for character in sample
        )
        if crib in output.casefold():
            prefix = f"Amount = {amount:2d}: " if print_amount else ""
            lines.append(prefix + _escape_whitespace(output))
    return "\n".join(lines)


@operation("XOR Brute Force", category="Ciphers")
def xor_brute_force(value: Data, args: Args) -> str:
    key_length = require_int(arg(args, 0, 1), name="key length")
    length = require_int(arg(args, 1, 100))
    offset = require_int(arg(args, 2, 0))
    scheme = str(arg(args, 3, "Standard"))
    null_preserving = bool(arg(args, 4, False))
    print_key = bool(arg(args, 5, True))
    output_hex = bool(arg(args, 6, False))
    crib = str(arg(args, 7, "")).casefold()
    if key_length not in {1, 2}:
        raise ValueError("key length must be 1 or 2 bytes")
    sample = to_bytes(value)[offset : offset + length]
    lines: list[str] = []
    for key_number in range(1, 256**key_length):
        key = key_number.to_bytes(key_length, "big")
        transformed = bytearray()
        previous_input = previous_output = 0
        for index, byte in enumerate(sample):
            result = byte if null_preserving and byte == 0 else byte ^ key[index % key_length]
            if scheme == "Input differential":
                result ^= previous_input
            elif scheme == "Output differential":
                result ^= previous_output
            transformed.append(result)
            previous_input, previous_output = byte, result
        raw = bytes(transformed)
        text = raw.decode("utf-8", "replace")
        if crib and crib not in text.casefold():
            continue
        rendered = raw.hex(" ") if output_hex else _escape_whitespace(text)
        prefix = f"Key = {key_number:0{key_length * 2}x}: " if print_key else ""
        lines.append(prefix + rendered)
    return "\n".join(lines)


@operation("TCP/IP Checksum", category="Hashing")
def tcp_ip_checksum(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    if len(data) % 2:
        data += b"\0"
    checksum = sum(
        int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2)
    )
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return f"{(~checksum) & 0xFFFF:04x}"


def _custom_base64(data: bytes, alphabet_specification: str) -> str:
    alphabet = expand_alphabet(alphabet_specification)
    if len(alphabet) != 65:
        raise ValueError("Base64 alphabet must contain 64 symbols and a padding symbol")
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    return base64.b64encode(data).decode().translate(str.maketrans(standard, alphabet))


def _static_base64_section(encoded: str, prefix: int) -> str:
    padding_index = encoded.find("=")
    if padding_index < 0:
        return encoded[prefix:]
    body = encoded[prefix:]
    return body[:-3] if padding_index % 4 == 2 else body[:-2] if padding_index % 4 == 3 else body


@operation("Show Base64 offsets", category="Encoding")
def show_base64_offsets(value: Data, args: Args) -> str:
    alphabet = str(arg(args, 0, "A-Za-z0-9+/="))
    show_variable = bool(arg(args, 1, True))
    input_format = str(arg(args, 2, "Raw"))
    data = base64.b64decode(to_bytes(value)) if input_format == "Base64" else to_bytes(value)
    if not data:
        raise ValueError("Please enter a string.")
    encoded = [_custom_base64(bytes(prefix) + data, alphabet) for prefix in range(3)]
    static = [
        _static_base64_section(encoded[0], 0),
        _static_base64_section(encoded[1], 2),
        _static_base64_section(encoded[2], 3),
    ]
    if not show_variable:
        return "\n".join(html.escape(section) for section in static)
    return "\n".join(f"Offset {index}: {html.escape(item)}" for index, item in enumerate(encoded))


def _transition_from_ipv4(address: ipaddress.IPv4Address, *, network: bool, headers: bool) -> str:
    packed = address.packed.hex()
    first, second = packed[:4], packed[4:]
    suffix_6to4 = f"{second}::/{40 if network else 48}"
    suffix_other = f"{second}/120" if network else second
    entries = (
        ("6to4: ", f"2002:{first}:{suffix_6to4}"),
        ("IPv4 Mapped: ", f"::ffff:{first}:{suffix_other}"),
        ("IPv4 Translated: ", f"::ffff:0:{first}:{suffix_other}"),
        ("Nat 64: ", f"64:ff9b::{first}:{suffix_other}"),
    )
    return "".join((label if headers else "") + rendered + "\n" for label, rendered in entries)


@operation("IPv6 Transition Addresses", category="Networking")
def ipv6_transition(value: Data, args: Args) -> str:
    ignore_ranges = bool(arg(args, 0, True))
    headers = not bool(arg(args, 1, False))
    output = ""
    for line in filter(None, (part.strip() for part in to_text(value).splitlines())):
        if "/" in line:
            if ignore_ranges:
                continue
            network = ipaddress.IPv4Network(line)
            if network.prefixlen != 24:
                raise ValueError("only IPv4 /24 ranges are supported")
            output += _transition_from_ipv4(network.network_address, network=True, headers=headers)
            continue
        try:
            address = ipaddress.ip_address(line)
        except ValueError:
            compact = line.replace("-", ":").lower()
            parts = compact.split(":")
            if len(parts) != 6 or any(len(part) != 2 for part in parts):
                raise ValueError("enter an IPv4, IPv6, /24, or MAC address") from None
            first = int(parts[0], 16) ^ 2
            identifier = f"{first:02x}{parts[1]}:{parts[2]}ff:fe{parts[3]}:{parts[4]}{parts[5]}"
            output += ("EUI-64 Interface ID: " if headers else "") + identifier
            continue
        if isinstance(address, ipaddress.IPv4Address):
            output += _transition_from_ipv4(address, network=False, headers=headers)
        else:
            embedded = ipaddress.IPv4Address(address.packed[-4:])
            output += ("IPv4: " if headers else "") + str(embedded) + "\n"
    return output
