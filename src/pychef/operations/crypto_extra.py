"""Pure-Python legacy hashes, KDFs, and one-time passwords."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import struct
import time
from typing import Any
from urllib.parse import quote

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int
from .ripemd_core import digest as _ripemd_digest

_MD2_TABLE = bytes(
    [
        41,
        46,
        67,
        201,
        162,
        216,
        124,
        1,
        61,
        54,
        84,
        161,
        236,
        240,
        6,
        19,
        98,
        167,
        5,
        243,
        192,
        199,
        115,
        140,
        152,
        147,
        43,
        217,
        188,
        76,
        130,
        202,
        30,
        155,
        87,
        60,
        253,
        212,
        224,
        22,
        103,
        66,
        111,
        24,
        138,
        23,
        229,
        18,
        190,
        78,
        196,
        214,
        218,
        158,
        222,
        73,
        160,
        251,
        245,
        142,
        187,
        47,
        238,
        122,
        169,
        104,
        121,
        145,
        21,
        178,
        7,
        63,
        148,
        194,
        16,
        137,
        11,
        34,
        95,
        33,
        128,
        127,
        93,
        154,
        90,
        144,
        50,
        39,
        53,
        62,
        204,
        231,
        191,
        247,
        151,
        3,
        255,
        25,
        48,
        179,
        72,
        165,
        181,
        209,
        215,
        94,
        146,
        42,
        172,
        86,
        170,
        198,
        79,
        184,
        56,
        210,
        150,
        164,
        125,
        182,
        118,
        252,
        107,
        226,
        156,
        116,
        4,
        241,
        69,
        157,
        112,
        89,
        100,
        113,
        135,
        32,
        134,
        91,
        207,
        101,
        230,
        45,
        168,
        2,
        27,
        96,
        37,
        173,
        174,
        176,
        185,
        246,
        28,
        70,
        97,
        105,
        52,
        64,
        126,
        15,
        85,
        71,
        163,
        35,
        221,
        81,
        175,
        58,
        195,
        92,
        249,
        206,
        186,
        197,
        234,
        38,
        44,
        83,
        13,
        110,
        133,
        40,
        132,
        9,
        211,
        223,
        205,
        244,
        65,
        129,
        77,
        82,
        106,
        220,
        55,
        200,
        108,
        193,
        171,
        250,
        36,
        225,
        123,
        8,
        12,
        189,
        177,
        74,
        120,
        136,
        149,
        139,
        227,
        99,
        232,
        109,
        233,
        203,
        213,
        254,
        59,
        0,
        29,
        57,
        242,
        239,
        183,
        14,
        102,
        88,
        208,
        228,
        166,
        119,
        114,
        248,
        235,
        117,
        75,
        10,
        49,
        68,
        80,
        180,
        143,
        237,
        31,
        26,
        219,
        153,
        141,
        51,
        159,
        17,
        131,
        20,
    ]
)


def _md2(data: bytes) -> bytes:
    padding = 16 - len(data) % 16
    data += bytes([padding]) * padding
    checksum = bytearray(16)
    previous = 0
    for offset in range(0, len(data), 16):
        for index, byte in enumerate(data[offset : offset + 16]):
            checksum[index] ^= _MD2_TABLE[byte ^ previous]
            previous = checksum[index]
    data += checksum
    state = bytearray(48)
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        for index in range(16):
            state[16 + index] = block[index]
            state[32 + index] = state[index] ^ block[index]
        previous = 0
        for round_number in range(18):
            for index in range(48):
                state[index] ^= _MD2_TABLE[previous]
                previous = state[index]
            previous = (previous + round_number) & 0xFF
    return bytes(state[:16])


def _left_rotate(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def _md4(data: bytes) -> bytes:
    original_bits = len(data) * 8
    data += b"\x80"
    data += b"\0" * ((56 - len(data)) % 64)
    data += struct.pack("<Q", original_bits)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    round1_shifts = (3, 7, 11, 19)
    round2_order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    round2_shifts = (3, 5, 9, 13)
    round3_order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    round3_shifts = (3, 9, 11, 15)
    for offset in range(0, len(data), 64):
        words = struct.unpack("<16I", data[offset : offset + 64])
        a, b, c, d = state
        for index in range(16):
            function = (b & c) | (~b & d)
            a = _left_rotate((a + function + words[index]) & 0xFFFFFFFF, round1_shifts[index % 4])
            a, b, c, d = d, a, b, c
        for index, word_index in enumerate(round2_order):
            function = (b & c) | (b & d) | (c & d)
            a = _left_rotate(
                (a + function + words[word_index] + 0x5A827999) & 0xFFFFFFFF,
                round2_shifts[index % 4],
            )
            a, b, c, d = d, a, b, c
        for index, word_index in enumerate(round3_order):
            function = b ^ c ^ d
            a = _left_rotate(
                (a + function + words[word_index] + 0x6ED9EBA1) & 0xFFFFFFFF,
                round3_shifts[index % 4],
            )
            a, b, c, d = d, a, b, c
        state = [
            (state[0] + a) & 0xFFFFFFFF,
            (state[1] + b) & 0xFFFFFFFF,
            (state[2] + c) & 0xFFFFFFFF,
            (state[3] + d) & 0xFFFFFFFF,
        ]
    return struct.pack("<4I", *state)


def _sha0(data: bytes) -> bytes:
    bit_length = len(data) * 8
    data += b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack(">Q", bit_length)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for offset in range(0, len(data), 64):
        words = list(struct.unpack(">16I", data[offset : offset + 64])) + [0] * 64
        for index in range(16, 80):
            words[index] = (
                words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]
            )
        a, b, c, d, e = state
        for index in range(80):
            if index < 20:
                function, constant = (b & c) | (~b & d), 0x5A827999
            elif index < 40:
                function, constant = b ^ c ^ d, 0x6ED9EBA1
            elif index < 60:
                function, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                function, constant = b ^ c ^ d, 0xCA62C1D6
            temporary = (_left_rotate(a, 5) + function + e + constant + words[index]) & 0xFFFFFFFF
            a, b, c, d, e = temporary, a, _left_rotate(b, 30), c, d
        state = [
            (left + right) & 0xFFFFFFFF for left, right in zip(state, (a, b, c, d, e), strict=True)
        ]
    return struct.pack(">5I", *state)


@implementation("MD2", category="Hashing")
def md2(value: Data, _args: Args) -> str:
    return _md2(to_bytes(value)).hex()


@implementation("MD4", category="Hashing")
def md4(value: Data, _args: Args) -> str:
    return _md4(to_bytes(value)).hex()


@implementation("SHA0", category="Hashing")
def sha0(value: Data, _args: Args) -> str:
    return _sha0(to_bytes(value)).hex()


@implementation("NT Hash", category="Hashing")
def nt_hash(value: Data, _args: Args) -> str:
    return _md4(to_text(value).encode("utf-16le")).hex().upper()


@implementation("RIPEMD", category="Hashing")
def ripemd(value: Data, args: Args) -> str:
    size = require_int(arg(args, 0, "160"), name="digest size")
    return _ripemd_digest(to_bytes(value), size).hex()


@implementation("SM3", category="Hashing")
def sm3(value: Data, _args: Args) -> str:
    return hashlib.new("sm3", to_bytes(value)).hexdigest()


def _toggle_bytes(value: Any) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        option = str(value.get("option", "UTF8"))
    else:
        text, option = str(value or ""), "UTF8"
    if option == "Hex":
        return bytes.fromhex(text)
    if option == "Base64":
        return base64.b64decode(text)
    if option == "Decimal":
        return bytes(int(token) for token in text.replace(",", " ").split())
    if option == "Latin1":
        return text.encode("latin-1")
    return text.encode()


@implementation("Derive PBKDF2 key", category="KDF")
def derive_pbkdf2(value: Data, args: Args) -> str:
    passphrase = _toggle_bytes(arg(args, 0, {"string": "", "option": "UTF8"}))
    key_bits = require_int(arg(args, 1, 128))
    iterations = require_int(arg(args, 2, 1))
    algorithm = str(arg(args, 3, "SHA1")).lower()
    salt = _toggle_bytes(arg(args, 4, {"string": "", "option": "Hex"})) or to_bytes(value)
    return hashlib.pbkdf2_hmac(algorithm, passphrase, salt, iterations, key_bits // 8).hex()


@implementation("Derive HKDF key", category="KDF")
def derive_hkdf(value: Data, args: Args) -> str:
    salt = _toggle_bytes(arg(args, 0, {"string": "", "option": "Hex"}))
    info = _toggle_bytes(arg(args, 1, {"string": "", "option": "Hex"}))
    algorithm = str(arg(args, 2, "SHA256")).lower().replace("/", "_")
    mode = str(arg(args, 3, "with salt"))
    length = require_int(arg(args, 4, 16))
    digest_size = hashlib.new(algorithm).digest_size
    if not 0 <= length <= 255 * digest_size:
        raise ValueError("HKDF output length is out of range")
    ikm = to_bytes(value)
    if mode == "skip":
        pseudorandom_key = ikm
    else:
        pseudorandom_key = hmac.new(
            salt if mode == "with salt" else bytes(digest_size), ikm, algorithm
        ).digest()
    result = previous = b""
    for counter in range(1, math.ceil(length / digest_size) + 1):
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes([counter]), algorithm
        ).digest()
        result += previous
    return result[:length].hex()


@implementation("Derive EVP key", category="KDF")
def derive_evp(_value: Data, args: Args) -> str:
    passphrase = _toggle_bytes(arg(args, 0, {"string": "", "option": "UTF8"}))
    key_bits = require_int(arg(args, 1, 128))
    iterations = require_int(arg(args, 2, 1))
    algorithm = str(arg(args, 3, "MD5")).lower()
    salt = _toggle_bytes(arg(args, 4, {"string": "", "option": "Hex"}))
    if key_bits < 1 or key_bits % 8:
        raise ValueError("key size must be a positive multiple of 8 bits")
    if iterations < 1:
        raise ValueError("iterations must be positive")
    output = previous = b""
    while len(output) < key_bits // 8:
        digest = previous + passphrase + salt
        for _ in range(iterations):
            digest = hashlib.new(algorithm, digest).digest()
        previous = digest
        output += digest
    return output[: key_bits // 8].hex()


def _hotp(secret: bytes, counter: int, digits: int) -> str:
    digest = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0xF
    number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{number % (10**digits):0{digits}d}"


def _otp_output(
    value: Data, name: str, digits: int, counter: int, kind: str, period: int = 30
) -> str:
    if not name:
        raise ValueError("Name cannot be empty.")
    if digits < 6:
        raise ValueError("Code length must be greater than or equal to 6.")
    if digits > 8:
        raise ValueError("Code length must be less than or equal to 8.")
    if counter < 0:
        raise ValueError("Counter must be greater than or equal to 0.")
    normalized = "".join(to_text(value).upper().split())
    secret = base64.b32decode(normalized + "=" * (-len(normalized) % 8))
    uri = f"otpauth://{kind}/{quote(name)}?secret={normalized}&algorithm=SHA1&digits={digits}"
    if kind == "hotp":
        uri += f"&counter={counter}"
    else:
        uri += f"&period={period}"
    return f"URI: {uri}\n\nPassword: {_hotp(secret, counter, digits)}"


@implementation("Generate HOTP", category="KDF")
def generate_hotp(value: Data, args: Args) -> str:
    return _otp_output(
        value,
        str(arg(args, 0, "Account")),
        require_int(arg(args, 1, 6)),
        require_int(arg(args, 2, 0)),
        "hotp",
    )


@implementation("Generate TOTP", category="KDF")
def generate_totp(value: Data, args: Args) -> str:
    digits = require_int(arg(args, 1, 6))
    epoch = require_int(arg(args, 2, 0))
    period = require_int(arg(args, 3, 30))
    counter = int((time.time() - epoch) // period)
    return _otp_output(value, str(arg(args, 0, "Account")), digits, counter, "totp", period)


@implementation("Luhn Checksum", category="Hashing")
def luhn_checksum(value: Data, args: Args) -> str:
    radix = require_int(arg(args, 0, 10))
    text = to_text(value).strip()
    if not text:
        return ""
    if not 2 <= radix <= 36:
        raise ValueError("Error: Radix argument must be between 2 and 36")
    if radix % 2:
        raise ValueError("Error: Radix argument must be divisible by 2")

    def checksum(source: str) -> int:
        total = 0
        for index, character in enumerate(reversed(source)):
            try:
                digit = int(character, radix)
            except ValueError as exc:
                raise ValueError(f"Character: {character} is not valid in radix {radix}.") from exc
            if index % 2:
                digit *= 2
                digit = digit // radix + digit % radix
            total += digit
        return total % radix

    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    checksum_value = checksum(text)
    checkdigit_value = checksum(text + "0")
    checkdigit_value = 0 if checkdigit_value == 0 else radix - checkdigit_value
    checkdigit = alphabet[checkdigit_value]
    return (
        f"Checksum: {alphabet[checksum_value]}\nCheckdigit: {checkdigit}\n"
        f"Luhn Validated String: {text}{checkdigit}"
    )


@implementation("Analyse hash", category="Analysis")
def analyse_hash(value: Data, _args: Args) -> str:
    text = "".join(to_text(value).split())
    if not text or any(character not in "0123456789abcdefABCDEF" for character in text):
        raise ValueError("invalid hash")
    bits = len(text) * 4
    candidates = {
        128: ("MD5", "MD4", "MD2"),
        160: ("SHA-1", "SHA-0", "RIPEMD-160"),
        224: ("SHA-224", "SHA3-224"),
        256: ("SHA-256", "SHA3-256", "BLAKE2s"),
        384: ("SHA-384", "SHA3-384"),
        512: ("SHA-512", "SHA3-512", "BLAKE2b"),
    }.get(bits, ("Unknown",))
    description = (
        "Based on the length, this hash could have been generated by one of the "
        "following hashing functions:\n"
    )
    return (
        f"Hash length: {len(text)}\nByte length: {len(text) // 2}\nBit length:  {bits}\n\n"
        + description
        + "\n".join(candidates)
    )


@implementation("Extract hashes", category="Extraction")
def extract_hashes(value: Data, args: Args) -> str:
    length = require_int(arg(args, 0, 40))
    all_hashes = bool(arg(args, 1, False))
    display_total = bool(arg(args, 2, False))
    pattern = r"(?i)(?<![0-9a-f])[0-9a-f]{%s}(?![0-9a-f])" % (
        "32,128" if all_hashes else str(length)
    )
    matches = re.findall(pattern, to_text(value))
    output = "\n".join(matches)
    return f"Total found: {len(matches)}\n\n{output}" if display_total else output
