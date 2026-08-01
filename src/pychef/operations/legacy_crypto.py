"""Dependency-free KDF, fuzzy hashing, and legacy cryptographic operations."""

from __future__ import annotations

import base64
import hashlib
import math
import secrets
import zlib

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, require_int
from .crc_models import CRC_MODELS
from .crypto_extra import _md2, _md4, _sha0
from .des import lm_hash as _lm_hash
from .gost_core import crypt as _gost_crypt_bytes
from .gost_core import gost94 as _gost94_digest
from .gost_core import mac as _gost_mac
from .gost_core import unwrap_key as _gost_unwrap_key
from .gost_core import wrap_key as _gost_wrap_key
from .has160 import _digest as _has160_digest
from .hashing import _crc
from .keccak import _keccak
from .md6_core import md6 as _md6_digest
from .ripemd_core import digest as _ripemd_digest
from .snefru_core import snefru as _snefru_digest
from .streebog_core import streebog as _streebog_digest
from .twofish_core import decrypt_block as _twofish_decrypt_block
from .twofish_core import encrypt_block as _twofish_encrypt_block
from .whirlpool_core import whirlpool as _whirlpool_digest


def _toggle_bytes(value: object) -> bytes:
    if isinstance(value, dict):
        text = str(value.get("string", ""))
        option = str(value.get("option", "UTF8"))
    else:
        text = str(value)
        option = "UTF8"
    if option == "Hex":
        return bytes.fromhex(text)
    if option == "Base64":
        return base64.b64decode(text)
    if option == "Latin1":
        return text.encode("latin-1")
    return text.encode()


@implementation("Scrypt", category="KDF")
def scrypt(value: Data, args: Args) -> Data:
    salt = _toggle_bytes(arg(args, 0, {"option": "UTF8", "string": ""}))
    iterations = require_int(arg(args, 1, 16384), name="iterations")
    memory_factor = require_int(arg(args, 2, 8), name="memory factor")
    parallelization = require_int(arg(args, 3, 1), name="parallelization factor")
    length = require_int(arg(args, 4, 64), name="key length")
    if iterations < 2 or iterations & (iterations - 1):
        raise ValueError("Scrypt iterations must be a power of two greater than one")
    if not 1 <= memory_factor <= 1_048_576 or not 1 <= parallelization <= 1_048_576:
        raise ValueError("Scrypt r and p must be positive and bounded")
    if not 1 <= length <= 1_048_576:
        raise ValueError("Scrypt key length must be between 1 and 1048576 bytes")
    try:
        return hashlib.scrypt(
            to_bytes(value),
            salt=salt,
            n=iterations,
            r=memory_factor,
            p=parallelization,
            dklen=length,
        ).hex()
    except (MemoryError, OverflowError, ValueError) as exc:
        raise ValueError(f"Scrypt parameters are not feasible: {exc}") from exc


_FUZZY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class _RollingHash:
    def __init__(self) -> None:
        self.window = bytearray(7)
        self.first = 0
        self.second = 0
        self.third = 0
        self.position = 0

    def update(self, value: int) -> int:
        outgoing = self.window[self.position % 7]
        self.second = (self.second - self.first + 7 * value) & 0xFFFFFFFF
        self.first = (self.first + value - outgoing) & 0xFFFFFFFF
        self.window[self.position % 7] = value
        self.position += 1
        self.third = ((self.third << 5) ^ value) & 0xFFFFFFFF
        return (self.first + self.second + self.third) & 0xFFFFFFFF


def _ctph_fnv(value: int, byte: int) -> int:
    # ctph.js uses JavaScript's double multiplication rather than an integer
    # multiply, including its rounding above 2**53.
    return int(float(value) * 0x01000193) ^ byte


def _fuzzy_piece(
    data: bytes, block_size: int, *, ctph: bool, maximum_first: int | None = None
) -> tuple[str, str]:
    rolling = _RollingHash()
    first_hash = second_hash = 0x28021967
    first: list[str] = []
    second: list[str] = []
    for index, byte in enumerate(data):
        trigger = rolling.update(byte)
        if ctph:
            first_hash = _ctph_fnv(first_hash, byte) & 0xFFFFFFFF
            second_hash = _ctph_fnv(second_hash, byte) & 0xFFFFFFFF
        else:
            first_hash = ((first_hash * 0x01000193) ^ byte) & 0xFFFFFFFF
            second_hash = ((second_hash * 0x01000193) ^ byte) & 0xFFFFFFFF
        at_end = ctph and index == len(data) - 1
        if (at_end or trigger % block_size == block_size - 1) and (
            maximum_first is None or len(first) < maximum_first
        ):
            first.append(_FUZZY_ALPHABET[first_hash & 63])
            first_hash = 0x28021967
        if (at_end or trigger % (block_size * 2) == block_size * 2 - 1) and (
            maximum_first is None or len(second) < maximum_first // 2
        ):
            second.append(_FUZZY_ALPHABET[second_hash & 63])
            second_hash = 0x28021967
    if not ctph and data:
        first.append(_FUZZY_ALPHABET[first_hash & 63])
        second.append(_FUZZY_ALPHABET[second_hash & 63])
    return "".join(first), "".join(second)


def _ssdeep(data: bytes) -> str:
    block_size = 3
    while block_size * 64 < len(data):
        block_size *= 2
    while True:
        first, second = _fuzzy_piece(data, block_size, ctph=False, maximum_first=63)
        next_size = block_size // 2
        if next_size <= 3 or len(first) >= 32:
            break
        block_size = next_size
    return f"{block_size}:{first}:{second}"


def _ctph(data: bytes) -> str:
    ratio = len(data) / (64 * 3)
    exponent = math.ceil(math.log2(ratio)) if ratio else -1_000_000
    exponent = max(3, exponent)
    while True:
        first, second = _fuzzy_piece(data, 3 << exponent, ctph=True)
        if exponent <= 0 or len(first) >= 32:
            break
        exponent -= 1
    return f"{_FUZZY_ALPHABET[exponent]}:{first}:{second}"


def _levenshtein(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, 1):
        current = [row]
        for column, right_char in enumerate(right, 1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[column] + 1,
                    previous[column - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def _fuzzy_score(left: str, right: str, *, ctph: bool) -> float:
    if not left or not right:
        raise ValueError("Invalid fuzzy hash")
    first_index = _FUZZY_ALPHABET.find(left[0])
    second_index = _FUZZY_ALPHABET.find(right[0])
    if first_index > second_index:
        return _fuzzy_score(right, left, ctph=ctph)
    if abs(first_index - second_index) > 1:
        return 0.0
    try:
        _left_block, left_first, left_second = left.split(":", 2)
        _right_block, right_first, _right_second = right.split(":", 2)
    except ValueError as exc:
        raise ValueError("Invalid fuzzy hash") from exc
    first_signature, second_signature = (
        (left_first, right_first) if first_index == second_index else (left_second, right_first)
    )
    longest = max(len(first_signature), len(second_signature))
    if not longest:
        return 100.0
    return (1 - _levenshtein(first_signature, second_signature) / longest) * 100


@implementation("CTPH", category="Hashing")
def ctph(value: Data, args: Args) -> Data:
    del args
    return _ctph(to_bytes(value))


@implementation("SSDEEP", category="Hashing")
def ssdeep(value: Data, args: Args) -> Data:
    del args
    return _ssdeep(to_bytes(value))


def _compare_fuzzy(value: Data, args: Args, *, ctph: bool) -> Data:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    samples = to_text(value).split(delimiter)
    if len(samples) != 2:
        raise ValueError("Incorrect number of fuzzy-hash samples")
    score = _fuzzy_score(samples[0].strip(), samples[1].strip(), ctph=ctph)
    return str(int(score)) if float(score).is_integer() else str(score)


@implementation("Compare CTPH hashes", category="Hashing")
def compare_ctph(value: Data, args: Args) -> Data:
    return _compare_fuzzy(value, args, ctph=True)


@implementation("Compare SSDEEP hashes", category="Hashing")
def compare_ssdeep(value: Data, args: Args) -> Data:
    return _compare_fuzzy(value, args, ctph=False)


@implementation("MD6", category="Hashing")
def md6(value: Data, args: Args) -> Data:
    bits = require_int(arg(args, 0, 256), name="digest size")
    levels = require_int(arg(args, 1, 64), name="levels")
    key = str(arg(args, 2, "")).encode()
    if not 0 <= bits <= 512 or levels < 0:
        raise ValueError("MD6 size must be 0..512 and levels must not be negative")
    return _md6_digest(to_bytes(value), max(1, bits), key, levels).hex()


@implementation("Snefru", category="Hashing")
def snefru(value: Data, args: Args) -> Data:
    bits = require_int(arg(args, 0, 256), name="digest size")
    rounds = require_int(arg(args, 1, 8), name="rounds")
    return _snefru_digest(to_bytes(value), bits, rounds).hex()


@implementation("Streebog", category="Hashing")
def streebog(value: Data, args: Args) -> Data:
    bits = require_int(arg(args, 0, "256"), name="digest size")
    if bits not in {256, 512}:
        raise ValueError("Streebog digest size must be 256 or 512")
    return _streebog_digest(to_bytes(value), bits).hex()


@implementation("Whirlpool", category="Hashing")
def whirlpool(value: Data, args: Args) -> Data:
    version = str(arg(args, 0, "Whirlpool"))
    if version not in {"Whirlpool", "Whirlpool-T", "Whirlpool-0"}:
        raise ValueError("Unknown Whirlpool version")
    rounds = require_int(arg(args, 1, 10), name="rounds")
    return _whirlpool_digest(to_bytes(value), version, rounds).hex()


@implementation("GOST Hash", category="Hashing")
def gost_hash(value: Data, args: Args) -> Data:
    version = str(arg(args, 0, "GOST 28147 (1994)"))
    bits = require_int(arg(args, 1, "256"), name="digest size")
    if bits not in {256, 512}:
        raise ValueError("GOST digest size must be 256 or 512")
    if "Streebog" in version or "2012" in version:
        return _streebog_digest(to_bytes(value), bits).hex()
    sbox = str(arg(args, 2, "D-A"))
    return _gost94_digest(to_bytes(value), sbox).hex()


@implementation("Generate all hashes", category="Hashing")
def generate_all_hashes(value: Data, args: Args) -> Data:
    data = to_bytes(value)
    length = str(arg(args, 0, "All"))
    include_names_value = arg(args, 1, True)
    include_names = (
        include_names_value.lower() not in {"false", "0", "no"}
        if isinstance(include_names_value, str)
        else bool(include_names_value)
    )
    text = data.decode("latin-1")
    hashes = (
        ("MD2", _md2(data).hex()),
        ("MD4", _md4(data).hex()),
        ("MD5", hashlib.md5(data, usedforsecurity=False).hexdigest()),
        ("MD6", _md6_digest(data, 256).hex()),
        ("SHA0", _sha0(data).hex()),
        ("SHA1", hashlib.sha1(data, usedforsecurity=False).hexdigest()),
        ("SHA2 224", hashlib.sha224(data).hexdigest()),
        ("SHA2 256", hashlib.sha256(data).hexdigest()),
        ("SHA2 384", hashlib.sha384(data).hexdigest()),
        ("SHA2 512", hashlib.sha512(data).hexdigest()),
        ("SHA3 224", hashlib.sha3_224(data).hexdigest()),
        ("SHA3 256", hashlib.sha3_256(data).hexdigest()),
        ("SHA3 384", hashlib.sha3_384(data).hexdigest()),
        ("SHA3 512", hashlib.sha3_512(data).hexdigest()),
        ("Keccak 224", _keccak(data, 224).hex()),
        ("Keccak 256", _keccak(data, 256).hex()),
        ("Keccak 384", _keccak(data, 384).hex()),
        ("Keccak 512", _keccak(data, 512).hex()),
        ("Shake 128", hashlib.shake_128(data).hexdigest(32)),
        ("Shake 256", hashlib.shake_256(data).hexdigest(64)),
        ("RIPEMD-128", _ripemd_digest(data, 128).hex()),
        ("RIPEMD-160", _ripemd_digest(data, 160).hex()),
        ("RIPEMD-256", _ripemd_digest(data, 256).hex()),
        ("RIPEMD-320", _ripemd_digest(data, 320).hex()),
        ("HAS-160", _has160_digest(data, 80).hex()),
        ("Whirlpool-0", _whirlpool_digest(data, "Whirlpool-0", 10).hex()),
        ("Whirlpool-T", _whirlpool_digest(data, "Whirlpool-T", 10).hex()),
        ("Whirlpool", _whirlpool_digest(data, "Whirlpool", 10).hex()),
        ("BLAKE2b-128", hashlib.blake2b(data, digest_size=16).hexdigest()),
        ("BLAKE2b-160", hashlib.blake2b(data, digest_size=20).hexdigest()),
        ("BLAKE2b-256", hashlib.blake2b(data, digest_size=32).hexdigest()),
        ("BLAKE2b-384", hashlib.blake2b(data, digest_size=48).hexdigest()),
        ("BLAKE2b-512", hashlib.blake2b(data, digest_size=64).hexdigest()),
        ("BLAKE2s-128", hashlib.blake2s(data, digest_size=16).hexdigest()),
        ("BLAKE2s-160", hashlib.blake2s(data, digest_size=20).hexdigest()),
        ("BLAKE2s-256", hashlib.blake2s(data, digest_size=32).hexdigest()),
        ("Streebog-256", _streebog_digest(data, 256).hex()),
        ("Streebog-512", _streebog_digest(data, 512).hex()),
        ("GOST", _gost94_digest(data, "D-A").hex()),
        ("LM Hash", str(_lm_hash(text, []))),
        ("NT Hash", _md4(text.encode("utf-16le")).hex().upper()),
        ("SSDEEP", _ssdeep(data)),
        ("CTPH", _ctph(data)),
    )
    output: list[str] = []
    for name, digest in hashes:
        if length != "All" and len(digest) * 4 != require_int(length, name="length"):
            continue
        output.append(f"{name}:{' ' * (13 - len(name))}{digest}" if include_names else digest)
    return "\n".join(output) + ("\n" if output else "")


def _fletcher(data: bytes, width: int) -> int:
    modulus = {8: 15, 16: 255, 32: 65535, 64: 0xFFFFFFFF}[width]
    word_size = max(1, width // 16)
    first = second = 0
    for index in range(0, len(data), word_size):
        first = (first + int.from_bytes(data[index : index + word_size], "little")) % modulus
        second = (second + first) % modulus
    return (second << (width // 2)) | first


@implementation("Generate all checksums", category="Hashing")
def generate_all_checksums(value: Data, args: Args) -> Data:
    data = to_bytes(value)
    selected_length = str(arg(args, 0, "All"))
    include_names_value = arg(args, 1, True)
    include_names = (
        include_names_value.lower() not in {"false", "0", "no"}
        if isinstance(include_names_value, str)
        else bool(include_names_value)
    )
    checksums: list[tuple[str, int, str]] = []
    previous_width = 0
    for name, parameters in CRC_MODELS.items():
        width, polynomial, initial, reflect_input, reflect_output, xor_output = parameters
        if previous_width == 8 and width > 8:
            checksums.append(("Fletcher-8", 8, f"{_fletcher(data, 8):02x}"))
        if previous_width == 16 and width > 16:
            checksums.append(("Fletcher-16", 16, f"{_fletcher(data, 16):04x}"))
        if previous_width < 32 and width == 32:
            checksums.append(("Adler-32", 32, f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"))
        if previous_width == 32 and width > 32:
            checksums.append(("Fletcher-32", 32, f"{_fletcher(data, 32):08x}"))
        if previous_width == 64 and width > 64:
            checksums.append(("Fletcher-64", 64, f"{_fletcher(data, 64):016x}"))
        result = _crc(data, width, polynomial, initial, reflect_input, reflect_output, xor_output)
        checksums.append((name, width, f"{result:0{(width + 3) // 4}x}"))
        previous_width = width
    if previous_width == 64:
        checksums.append(("Fletcher-64", 64, f"{_fletcher(data, 64):016x}"))

    output = []
    for name, width, checksum in checksums:
        if selected_length != "All" and require_int(selected_length, name="length") != width:
            continue
        output.append(f"{name}:{' ' * (25 - len(name))}{checksum}" if include_names else checksum)
    return "\n".join(output) + ("\n" if output else "")


def _pkcs7(data: bytes, block_size: int) -> bytes:
    amount = block_size - len(data) % block_size
    return data + bytes([amount]) * amount


def _unpkcs7(data: bytes, block_size: int) -> bytes:
    if (
        not data
        or data[-1] < 1
        or data[-1] > block_size
        or data[-data[-1] :] != bytes([data[-1]]) * data[-1]
    ):
        raise ValueError("Invalid block padding")
    return data[: -data[-1]]


def _gost_cipher(value: Data, args: Args, decrypt: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    input_type = str(arg(args, 2, "Raw"))
    output_type = str(arg(args, 3, "Hex"))
    version = str(arg(args, 4, "GOST 28147 (1989)"))
    sbox = str(arg(args, 5, "E-A"))
    mode = str(arg(args, 6, "ECB"))
    key_meshing = str(arg(args, 7, "NO"))
    padding = str(arg(args, 8, "PKCS5"))
    data = bytes.fromhex(to_text(value)) if input_type == "Hex" else to_bytes(value)
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    result_data = _gost_crypt_bytes(
        data,
        key,
        iv,
        version=version,
        sbox=sbox,
        mode=mode,
        key_meshing=key_meshing,
        padding=padding,
        decrypt=decrypt,
    )
    return result_data.hex() if output_type == "Hex" else result_data


@implementation("GOST Encrypt", category="Ciphers")
def gost_encrypt(value: Data, args: Args) -> Data:
    return _gost_cipher(value, args, False)


@implementation("GOST Decrypt", category="Ciphers")
def gost_decrypt(value: Data, args: Args) -> Data:
    return _gost_cipher(value, args, True)


@implementation("GOST Sign", category="Ciphers")
def gost_sign(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    input_type = str(arg(args, 2, "Raw"))
    output_type = str(arg(args, 3, "Hex"))
    version = str(arg(args, 4, "GOST 28147 (1989)"))
    sbox = str(arg(args, 5, "E-A"))
    bits = require_int(arg(args, 6, 32), name="MAC length")
    data = bytes.fromhex(to_text(value)) if input_type == "Hex" else to_bytes(value)
    result = _gost_mac(data, key, iv, version=version, sbox=sbox, bits=bits)
    return result.hex() if output_type == "Hex" else result


@implementation("GOST Verify", category="Ciphers")
def gost_verify(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    expected = _toggle_bytes(arg(args, 2, {"option": "Hex", "string": ""}))
    input_type = str(arg(args, 3, "Raw"))
    version = str(arg(args, 4, "GOST 28147 (1989)"))
    sbox = str(arg(args, 5, "E-A"))
    data = bytes.fromhex(to_text(value)) if input_type == "Hex" else to_bytes(value)
    actual = _gost_mac(data, key, iv, version=version, sbox=sbox, bits=len(expected) * 8)
    return (
        "The signature matches"
        if secrets.compare_digest(actual, expected)
        else "The signature does not match"
    )


@implementation("GOST Key Wrap", category="Ciphers")
def gost_key_wrap(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    ukm = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    input_type = str(arg(args, 2, "Raw"))
    output_type = str(arg(args, 3, "Hex"))
    version = str(arg(args, 4, "GOST 28147 (1989)"))
    sbox = str(arg(args, 5, "E-A"))
    method = str(arg(args, 6, "NO"))
    data = bytes.fromhex(to_text(value)) if input_type == "Hex" else to_bytes(value)
    result = _gost_wrap_key(data, key, ukm, version=version, sbox=sbox, method=method)
    if output_type == "Raw":
        return result
    encoded = result.hex()
    return encoded if len(result) <= 32 else f"{encoded[:64]}\r\n{encoded[64:]}"


@implementation("GOST Key Unwrap", category="Ciphers")
def gost_key_unwrap(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    ukm = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    input_type = str(arg(args, 2, "Hex"))
    output_type = str(arg(args, 3, "Raw"))
    version = str(arg(args, 4, "GOST 28147 (1989)"))
    sbox = str(arg(args, 5, "E-A"))
    method = str(arg(args, 6, "NO"))
    data = bytes.fromhex(to_text(value)) if input_type == "Hex" else to_bytes(value)
    result = _gost_unwrap_key(data, key, ukm, version=version, sbox=sbox, method=method)
    return result.hex() if output_type == "Hex" else result


def _twofish_padding(data: bytes, padding: str) -> bytes:
    remainder = len(data) % 16
    amount = 16 - remainder if remainder else 0
    if padding == "PKCS5":
        amount = amount or 16
        return data + bytes([amount]) * amount
    if not amount:
        return data
    if padding == "NO":
        raise ValueError("Twofish input must be a multiple of 16 bytes without padding")
    if padding == "ZERO":
        return data + b"\0" * amount
    if padding == "RANDOM":
        return data + secrets.token_bytes(amount)
    if padding == "BIT":
        return data + b"\x80" + b"\0" * (amount - 1)
    raise ValueError(f"Unknown Twofish padding: {padding}")


def _twofish_unpadding(data: bytes, padding: str) -> bytes:
    if padding in {"NO", "ZERO", "RANDOM"}:
        return data
    if padding == "PKCS5":
        return _unpkcs7(data, 16)
    if padding == "BIT":
        marker = len(data) - 1
        while marker >= 0 and data[marker] == 0:
            marker -= 1
        if marker < 0 or data[marker] != 0x80:
            raise ValueError("Invalid BIT padding")
        return data[:marker]
    raise ValueError(f"Unknown Twofish padding: {padding}")


def _twofish_counter_increment(counter: bytes) -> bytes:
    output = bytearray(counter)
    for index in range(16):
        output[index] = (output[index] + 1) & 0xFF
        if output[index]:
            break
    return bytes(output)


def _twofish_xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _twofish_crypt(value: Data, args: Args, decrypt: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    if len(key) not in {16, 24, 32}:
        raise ValueError("Twofish key must contain 16, 24, or 32 bytes")
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    mode = str(arg(args, 2, "CBC")).upper()
    legacy_arguments = len(args) < 6
    input_type = "Raw" if legacy_arguments else str(arg(args, 3, "Hex" if decrypt else "Raw"))
    output_type = "Raw" if legacy_arguments else str(arg(args, 4, "Raw" if decrypt else "Hex"))
    padding = str(arg(args, 3 if legacy_arguments else 5, "PKCS5"))
    padding = {"PKCS7": "PKCS5", "NoPadding": "NO"}.get(padding, padding).upper()
    data = bytes.fromhex(to_text(value)) if input_type.lower() == "hex" else to_bytes(value)
    if not data:
        return "" if output_type.lower() == "hex" else b""
    if mode not in {"ECB", "CBC", "CFB", "OFB", "CTR"}:
        raise ValueError(f"Invalid Twofish block cipher mode: {mode}")
    if mode != "ECB" and len(iv) != 16:
        raise ValueError("Twofish IV must contain 16 bytes")
    if mode == "ECB":
        iv = b"\0" * 16
    if not decrypt and mode in {"ECB", "CBC"}:
        data = _twofish_padding(data, padding)
    if decrypt and mode in {"ECB", "CBC"} and len(data) % 16:
        raise ValueError("Twofish ciphertext must contain complete 16-byte blocks")

    output = bytearray()
    previous = iv
    counter = iv
    for index in range(0, len(data), 16):
        block = data[index : index + 16]
        if mode == "ECB":
            result = (
                _twofish_decrypt_block(block, key)
                if decrypt
                else _twofish_encrypt_block(block, key)
            )
        elif mode == "CBC":
            if decrypt:
                result = _twofish_xor(_twofish_decrypt_block(block, key), previous)
                previous = block
            else:
                result = _twofish_encrypt_block(_twofish_xor(block, previous), key)
                previous = result
        elif mode == "CFB":
            stream = _twofish_encrypt_block(previous, key)
            result = bytes(a ^ b for a, b in zip(block, stream, strict=False))
            previous = block if decrypt else result
        elif mode == "OFB":
            previous = _twofish_encrypt_block(previous, key)
            result = bytes(a ^ b for a, b in zip(block, previous, strict=False))
        else:
            stream = _twofish_encrypt_block(counter, key)
            result = bytes(a ^ b for a, b in zip(block, stream, strict=False))
            counter = _twofish_counter_increment(counter)
        output.extend(result)
    result_data = bytes(output)
    if decrypt and mode in {"ECB", "CBC"}:
        result_data = _twofish_unpadding(result_data, padding)
    return result_data.hex() if output_type.lower() == "hex" else result_data


@implementation("Twofish Encrypt", category="Ciphers")
def twofish_encrypt(value: Data, args: Args) -> Data:
    return _twofish_crypt(value, args, False)


@implementation("Twofish Decrypt", category="Ciphers")
def twofish_decrypt(value: Data, args: Args) -> Data:
    return _twofish_crypt(value, args, True)
