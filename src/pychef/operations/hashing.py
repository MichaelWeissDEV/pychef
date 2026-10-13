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

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int
from .crc_models import CRC_MODELS
from .sha_custom import sha1 as _sha1
from .sha_custom import sha256 as _sha256
from .sha_custom import sha512 as _sha512


def _digest(name: str, value: Data) -> str:
    try:
        return hashlib.new(name, to_bytes(value)).hexdigest()
    except ValueError as exc:
        raise ValueError(f"hash algorithm is unavailable in this Python build: {name}") from exc


@implementation("MD5", category="Hashing")
def md5(value: Data, _args: Args) -> str:
    return _digest("md5", value)


@implementation("SHA1", category="Hashing")
def sha1(value: Data, args: Args) -> str:
    rounds = require_int(arg(args, 0, 80), name="rounds")
    data = to_bytes(value)
    if rounds == 80:
        return hashlib.sha1(data).hexdigest()
    return _sha1(data, rounds).hex()


@implementation("SHA2", category="Hashing")
def sha2(value: Data, args: Args) -> str:
    size = str(arg(args, 0, "512"))
    data = to_bytes(value)
    if size in {"224", "256"}:
        rounds = require_int(arg(args, 1, 64), name="rounds")
        if rounds == 64:
            if size == "256":
                return hashlib.sha256(data).hexdigest()
            return hashlib.sha224(data).hexdigest()
        return _sha256(data, int(size), rounds).hex()
    bits = {"384": 384, "512": 512, "512/224": 224, "512/256": 256}.get(size)
    if bits is None:
        raise ValueError(f"unsupported SHA-2 size: {size}")
    rounds = require_int(arg(args, 2, 160), name="rounds")
    if rounds == 160:
        if size == "384":
            return hashlib.sha384(data).hexdigest()
        if size == "512":
            return hashlib.sha512(data).hexdigest()
        if size == "512/224" and hasattr(hashlib, "sha512_224"):
            return hashlib.sha512_224(data).hexdigest()
        if size == "512/256" and hasattr(hashlib, "sha512_256"):
            return hashlib.sha512_256(data).hexdigest()
    return _sha512(data, bits, rounds).hex()


@implementation("SHA3", category="Hashing")
def sha3(value: Data, args: Args) -> str:
    size = str(arg(args, 0, "512"))
    return _digest(f"sha3_{size}", value)


@implementation("Shake", category="Hashing")
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


@implementation("BLAKE2b", category="Hashing")
def blake2b(value: Data, args: Args) -> Data:
    size_bits = require_int(arg(args, 0, "512"), name="size")
    output = str(arg(args, 1, "Hex"))
    key = _toggle_bytes(arg(args, 2, {"string": "", "option": "UTF8"}))
    digest = hashlib.blake2b(to_bytes(value), digest_size=size_bits // 8, key=key).digest()
    return _format_digest(digest, output)


@implementation("BLAKE2s", category="Hashing")
def blake2s(value: Data, args: Args) -> Data:
    size_bits = require_int(arg(args, 0, "256"), name="size")
    output = str(arg(args, 1, "Hex"))
    key = _toggle_bytes(arg(args, 2, {"string": "", "option": "UTF8"}))
    digest = hashlib.blake2s(to_bytes(value), digest_size=size_bits // 8, key=key).digest()
    return _format_digest(digest, output)


@implementation("HMAC", category="Hashing")
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


@implementation("Adler-32 Checksum", category="Hashing")
def adler32(value: Data, _args: Args) -> str:
    return f"{zlib.adler32(to_bytes(value)) & 0xFFFFFFFF:08x}"


@implementation("XOR Checksum", category="Hashing")
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


@implementation("Fletcher-8 Checksum", category="Hashing")
def fletcher8(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 1, 0xF)
    return f"{(second << 4) | first:02x}"


@implementation("Fletcher-16 Checksum", category="Hashing")
def fletcher16(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 1, 0xFF)
    return f"{(second << 8) | first:04x}"


@implementation("Fletcher-32 Checksum", category="Hashing")
def fletcher32(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 2, 0xFFFF)
    return f"{((second << 16) | first) & 0xFFFFFFFF:08x}"


@implementation("Fletcher-64 Checksum", category="Hashing")
def fletcher64(value: Data, _args: Args) -> str:
    first, second = _fletcher(to_bytes(value), 4, 0xFFFFFFFF)
    return f"{second & 0xFFFFFFFF:08x}{first & 0xFFFFFFFF:08x}"


@implementation("MurmurHash3", category="Hashing")
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


@implementation("Entropy", category="Analysis")
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


@implementation("Hamming Distance", category="Analysis")
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


@implementation("Index of Coincidence", category="Analysis")
def index_of_coincidence(value: Data, _args: Args) -> str:
    text = to_text(value)
    if len(text) < 2:
        return "0"
    counts = Counter(text)
    result = sum(count * (count - 1) for count in counts.values()) / (len(text) * (len(text) - 1))
    return str(result)


@implementation("Chi Square", category="Analysis")
def chi_square(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    if not data:
        return "0"
    expected = len(data) / 256
    counts = Counter(data)
    result = sum(((counts.get(byte, 0) - expected) ** 2) / expected for byte in range(256))
    return str(result)


@implementation("CRC Checksum", category="Hashing")
def crc_checksum(value: Data, args: Args) -> str:
    name = str(arg(args, 0, "CRC-32/ISO-HDLC"))
    data = to_bytes(value)
    if name == "Custom":

        def text_argument(index: int, default: str) -> str:
            value = arg(args, index, default)
            return str(value.get("string", default)) if isinstance(value, dict) else str(value)

        width = int(text_argument(1, "8"), 10)

        def hexadecimal(index: int, default: str) -> int:
            text = text_argument(index, default)
            return int(text, 0) if text.lower().startswith("0x") else int(text, 16)

        polynomial = hexadecimal(2, "07")
        initial = hexadecimal(3, "00")
        reflect_input = str(arg(args, 4, "False")).lower() in {"true", "1"}
        reflect_output = str(arg(args, 5, "False")).lower() in {"true", "1"}
        xor_output = hexadecimal(6, "00")
        parameters = width, polynomial, initial, reflect_input, reflect_output, xor_output
    else:
        aliases = {"CRC-32C": "CRC-32/CASTAGNOLI", "CRC-16/IBM": "CRC-16/ARC"}
        try:
            parameters = CRC_MODELS[aliases.get(name, name)]
        except KeyError as exc:
            raise ValueError(f"Unknown CRC model: {name}") from exc
    width, polynomial, initial, reflect_input, reflect_output, xor_output = parameters
    if not 1 <= width <= 4096:
        raise ValueError("CRC width must be between 1 and 4096 bits")
    result = _crc(data, width, polynomial, initial, reflect_input, reflect_output, xor_output)
    return f"{result:0{(width + 3) // 4}x}"


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
        for input_bit in (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01):
            feedback = register & top_bit
            register = (register << 1) & mask
            if byte & input_bit:
                feedback ^= top_bit
            if feedback:
                register ^= polynomial
    if reflect_output:
        register = _reflect(register, width)
    return (register ^ xor_output) & mask
