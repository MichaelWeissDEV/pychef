"""Hash, MAC, checksum, and statistical operations.

Behavior is compatible with CyberChef where documented. Rewritten in Python;
upstream CyberChef is Crown Copyright 2016 and Apache-2.0 licensed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import zlib
from collections import Counter
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int


def _digest(name: str, value: Data) -> str:
    try:
        return hashlib.new(name, to_bytes(value)).hexdigest()
    except ValueError as exc:
        raise ValueError(f"hash algorithm is unavailable in this Python build: {name}") from exc


@operation("MD5", category="Hashing")
def md5(value: Data, _args: Args) -> str:
    return _digest("md5", value)


@operation("SHA1", category="Hashing")
def sha1(value: Data, args: Args) -> str:
    rounds = require_int(arg(args, 0, 80), name="rounds")
    if rounds != 80:
        raise ValueError("custom SHA-1 rounds are not implemented")
    return _digest("sha1", value)


@operation("SHA2", category="Hashing")
def sha2(value: Data, args: Args) -> str:
    size = str(arg(args, 0, "512"))
    algorithm = {
        "224": "sha224",
        "256": "sha256",
        "384": "sha384",
        "512": "sha512",
        "512/224": "sha512_224",
        "512/256": "sha512_256",
    }.get(size)
    if algorithm is None:
        raise ValueError(f"unsupported SHA-2 size: {size}")
    return _digest(algorithm, value)


@operation("SHA3", category="Hashing")
def sha3(value: Data, args: Args) -> str:
    size = str(arg(args, 0, "512"))
    return _digest(f"sha3_{size}", value)


@operation("Shake", category="Hashing")
def shake(value: Data, args: Args) -> str:
    capacity = str(arg(args, 0, "256"))
    size_bits = require_int(arg(args, 1, 512), name="size")
    if size_bits < 0 or size_bits % 8:
        raise ValueError("SHAKE output size must be a non-negative multiple of 8 bits")
    constructor = hashlib.shake_256 if capacity == "256" else hashlib.shake_128
    return constructor(to_bytes(value)).hexdigest(size_bits // 8)


def _toggle_bytes(value: Any) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        encoding = str(value.get("option", "UTF8"))
    else:
        text = str(value or "")
        encoding = "UTF8"
    if encoding == "Hex":
        return bytes.fromhex(text)
    if encoding == "Base64":
        return base64.b64decode(text)
    if encoding == "Decimal":
        return bytes(int(token) & 0xFF for token in text.replace(",", " ").split())
    if encoding == "Latin1":
        return text.encode("latin-1")
    return text.encode("utf-8")


def _format_digest(digest: bytes, output: str) -> Data:
    if output == "Hex":
        return digest.hex()
    if output == "Base64":
        return base64.b64encode(digest).decode("ascii")
    if output == "Raw":
        return digest
    raise ValueError(f"unsupported output encoding: {output}")


@operation("BLAKE2b", category="Hashing")
def blake2b(value: Data, args: Args) -> Data:
    size_bits = require_int(arg(args, 0, "512"), name="size")
    output = str(arg(args, 1, "Hex"))
    key = _toggle_bytes(arg(args, 2, {"string": "", "option": "UTF8"}))
    digest = hashlib.blake2b(to_bytes(value), digest_size=size_bits // 8, key=key).digest()
    return _format_digest(digest, output)


@operation("BLAKE2s", category="Hashing")
def blake2s(value: Data, args: Args) -> Data:
    size_bits = require_int(arg(args, 0, "256"), name="size")
    output = str(arg(args, 1, "Hex"))
    key = _toggle_bytes(arg(args, 2, {"string": "", "option": "UTF8"}))
    digest = hashlib.blake2s(to_bytes(value), digest_size=size_bits // 8, key=key).digest()
    return _format_digest(digest, output)


@operation("HMAC", category="Hashing")
def hmac_hash(value: Data, args: Args) -> str:
    key = _toggle_bytes(arg(args, 0, {"string": "", "option": "Hex"}))
    requested = str(arg(args, 1, "SHA256")).upper().replace("-", "")
    algorithm = {
        "MD5": "md5",
        "SHA1": "sha1",
        "SHA224": "sha224",
        "SHA256": "sha256",
        "SHA384": "sha384",
        "SHA512": "sha512",
        "SHA512/224": "sha512_224",
        "SHA512/256": "sha512_256",
        "RIPEMD160": "ripemd160",
    }.get(requested)
    if algorithm is None:
        raise ValueError(f"unsupported HMAC hash: {requested}")
    return hmac.new(key, to_bytes(value), algorithm).hexdigest()


@operation("Adler-32 Checksum", category="Hashing")
def adler32(value: Data, _args: Args) -> str:
    return f"{zlib.adler32(to_bytes(value)) & 0xFFFFFFFF:08x}"


@operation("XOR Checksum", category="Hashing")
def xor_checksum(value: Data, args: Args) -> str:
    block_size = require_int(arg(args, 0, 4), name="block size")
    if block_size < 1:
        raise ValueError("block size must be positive")
    result = bytearray(block_size)
    for index, byte in enumerate(to_bytes(value)):
        result[index % block_size] ^= byte
    return result.hex()


def _fletcher(data: bytes, word_size: int, modulus: int) -> tuple[int, int]:
    first = second = 0
    for index in range(0, len(data), word_size):
        word = int.from_bytes(data[index : index + word_size], "little")
        first = (first + word) % modulus
        second = (second + first) % modulus
    return first, second


@operation("Fletcher-8 Checksum", category="Hashing")
def fletcher8(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 1, 0xF)
    return f"{(second << 4) | first:02x}"


@operation("Fletcher-16 Checksum", category="Hashing")
def fletcher16(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 1, 0xFF)
    return f"{(second << 8) | first:04x}"


@operation("Fletcher-32 Checksum", category="Hashing")
def fletcher32(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 2, 0xFFFF)
    return f"{((second << 16) | first) & 0xFFFFFFFF:08x}"


@operation("Fletcher-64 Checksum", category="Hashing")
def fletcher64(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 4, 0xFFFFFFFF)
    return f"{second & 0xFFFFFFFF:08x}{first & 0xFFFFFFFF:08x}"


@operation("MurmurHash3", category="Hashing")
def murmur_hash3(value: Data, args: Args) -> str:
    seed = require_int(arg(args, 0, 0), name="seed") & 0xFFFFFFFF
    signed = bool(arg(args, 1, False))
    data = to_bytes(value)
    hash_value = seed
    c1, c2 = 0xCC9E2D51, 0x1B873593
    rounded_end = len(data) & ~0x3
    for index in range(0, rounded_end, 4):
        key = int.from_bytes(data[index : index + 4], "little")
        key = (key * c1) & 0xFFFFFFFF
        key = ((key << 15) | (key >> 17)) & 0xFFFFFFFF
        key = (key * c2) & 0xFFFFFFFF
        hash_value ^= key
        hash_value = ((hash_value << 13) | (hash_value >> 19)) & 0xFFFFFFFF
        hash_value = (hash_value * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded_end:]
    key = 0
    for offset, byte in enumerate(tail):
        key |= byte << (8 * offset)
    if tail:
        key = (key * c1) & 0xFFFFFFFF
        key = ((key << 15) | (key >> 17)) & 0xFFFFFFFF
        key = (key * c2) & 0xFFFFFFFF
        hash_value ^= key
    hash_value ^= len(data)
    hash_value ^= hash_value >> 16
    hash_value = (hash_value * 0x85EBCA6B) & 0xFFFFFFFF
    hash_value ^= hash_value >> 13
    hash_value = (hash_value * 0xC2B2AE35) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    if signed and hash_value & 0x80000000:
        return str(hash_value - 0x100000000)
    return str(hash_value)


@operation("Entropy", category="Analysis")
def entropy(value: Data, args: Args) -> str:
    visualisation = str(arg(args, 0, "Shannon scale"))
    if visualisation != "Shannon scale":
        raise ValueError("graphical entropy visualisations are not available in the library API")
    data = to_bytes(value)
    if not data:
        return "0"
    counts = Counter(data)
    result = -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())
    return str(result)


@operation("Hamming Distance", category="Analysis")
def hamming_distance(value: Data, args: Args) -> str:
    delimiter = str(arg(args, 0, "\n\n")).replace("\\n", "\n").replace("\\t", "\t")
    unit = str(arg(args, 1, "Byte"))
    input_type = str(arg(args, 2, "Raw string"))
    left, separator, right = to_text(value).partition(delimiter)
    if not separator:
        raise ValueError("input does not contain the configured delimiter")
    if input_type == "Hex":
        left_bytes, right_bytes = bytes.fromhex(left), bytes.fromhex(right)
    else:
        left_bytes, right_bytes = to_bytes(left), to_bytes(right)
    shared = min(len(left_bytes), len(right_bytes))
    if unit == "Bit":
        distance = sum(
            (left_bytes[index] ^ right_bytes[index]).bit_count() for index in range(shared)
        )
        distance += 8 * abs(len(left_bytes) - len(right_bytes))
    else:
        distance = sum(left_bytes[index] != right_bytes[index] for index in range(shared))
        distance += abs(len(left_bytes) - len(right_bytes))
    return str(distance)


@operation("Index of Coincidence", category="Analysis")
def index_of_coincidence(value: Data, _args: Args) -> str:
    text = to_text(value)
    if len(text) < 2:
        return "0"
    counts = Counter(text)
    result = sum(count * (count - 1) for count in counts.values()) / (len(text) * (len(text) - 1))
    return str(result)


@operation("Chi Square", category="Analysis")
def chi_square(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    if not data:
        return "0"
    expected = len(data) / 256
    counts = Counter(data)
    result = sum(((counts.get(byte, 0) - expected) ** 2) / expected for byte in range(256))
    return str(result)


@operation("CRC Checksum", category="Hashing")
def crc_checksum(value: Data, args: Args) -> str:
    name = str(arg(args, 0, "CRC-32/ISO-HDLC"))
    data = to_bytes(value)
    if name in {"CRC-32", "CRC-32/ISO-HDLC", "CRC-32/ADCCP"}:
        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    if name in {"CRC-32C", "CRC-32/CASTAGNOLI"}:
        return f"{_crc(data, 32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF):08x}"
    if name in {"CRC-16/ARC", "CRC-16/IBM"}:
        return f"{_crc(data, 16, 0x8005, 0, True, True, 0):04x}"
    if name == "Custom":
        width = require_int(arg(args, 1, 8), name="width")
        polynomial = int(str(arg(args, 2, "0x07")), 0)
        initial = int(str(arg(args, 3, "0x00")), 0)
        reflect_input = bool(arg(args, 4, False))
        reflect_output = bool(arg(args, 5, False))
        xor_output = int(str(arg(args, 6, "0x00")), 0)
        result = _crc(data, width, polynomial, initial, reflect_input, reflect_output, xor_output)
        return f"{result:0{(width + 3) // 4}x}"
    raise ValueError(f"CRC model is not implemented: {name}")


def _reflect(number: int, width: int) -> int:
    reflected = 0
    for _ in range(width):
        reflected = (reflected << 1) | (number & 1)
        number >>= 1
    return reflected


def _crc(
    data: bytes,
    width: int,
    polynomial: int,
    initial: int,
    reflect_input: bool,
    reflect_output: bool,
    xor_output: int,
) -> int:
    mask = (1 << width) - 1
    register = initial & mask
    top_bit = 1 << (width - 1)
    for byte in data:
        if reflect_input:
            byte = _reflect(byte, 8)
        if width >= 8:
            register ^= byte << (width - 8)
            rounds = 8
        else:
            register ^= byte >> (8 - width)
            rounds = width
        for _ in range(rounds):
            register = (
                ((register << 1) ^ polynomial) & mask
                if register & top_bit
                else (register << 1) & mask
            )
    if reflect_output:
        register = _reflect(register, width)
    return (register ^ xor_output) & mask
