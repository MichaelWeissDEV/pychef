"""Dependency-free KDF, fuzzy hashing, and legacy cryptographic operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import zlib
from difflib import SequenceMatcher

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, require_int


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


@operation("Scrypt", category="KDF")
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
        self.window[self.position % 7] = value
        self.position += 1
        self.first = (self.first + value - outgoing) & 0xFFFFFFFF
        self.second = (self.second + self.first - 7 * outgoing) & 0xFFFFFFFF
        self.third = ((self.third << 5) ^ value) & 0xFFFFFFFF
        return (self.first + self.second + self.third) & 0xFFFFFFFF


def _fuzzy_piece(data: bytes, block_size: int) -> str:
    rolling = _RollingHash()
    digest = 0x28021967
    output: list[str] = []
    for byte in data:
        trigger = rolling.update(byte)
        digest = ((digest * 0x01000193) ^ byte) & 0xFFFFFFFF
        if trigger % block_size == block_size - 1:
            output.append(_FUZZY_ALPHABET[digest % 64])
            digest = 0x28021967
            if len(output) == 63:
                break
    if digest != 0x28021967 or not output:
        output.append(_FUZZY_ALPHABET[digest % 64])
    return "".join(output)


def _fuzzy(data: bytes) -> str:
    block_size = 3
    while block_size * 64 < len(data):
        block_size *= 2
    while block_size > 3:
        first = _fuzzy_piece(data, block_size)
        if len(first) >= 32:
            break
        block_size //= 2
    return f"{block_size}:{_fuzzy_piece(data, block_size)}:{_fuzzy_piece(data, block_size * 2)}"


def _fuzzy_score(left: str, right: str) -> int:
    try:
        left_size, left_first, left_second = left.split(":", 2)
        right_size, right_first, right_second = right.split(":", 2)
        first_size, second_size = int(left_size), int(right_size)
    except ValueError as exc:
        raise ValueError("Invalid fuzzy hash") from exc
    candidates: list[float] = []
    if first_size == second_size:
        candidates.append(SequenceMatcher(None, left_first, right_first).ratio())
        candidates.append(SequenceMatcher(None, left_second, right_second).ratio())
    elif first_size == second_size * 2:
        candidates.append(SequenceMatcher(None, left_first, right_second).ratio())
    elif second_size == first_size * 2:
        candidates.append(SequenceMatcher(None, left_second, right_first).ratio())
    return round(100 * max(candidates, default=0.0))


@operation("CTPH", category="Hashing")
def ctph(value: Data, args: Args) -> Data:
    del args
    return _fuzzy(to_bytes(value))


@operation("SSDEEP", category="Hashing")
def ssdeep(value: Data, args: Args) -> Data:
    del args
    return _fuzzy(to_bytes(value))


def _compare_fuzzy(value: Data, args: Args) -> Data:
    delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    samples = to_text(value).split(delimiter)
    if len(samples) != 2:
        raise ValueError("Incorrect number of fuzzy-hash samples")
    return str(_fuzzy_score(samples[0].strip(), samples[1].strip()))


operation("Compare CTPH hashes", category="Hashing")(_compare_fuzzy)
operation("Compare SSDEEP hashes", category="Hashing")(_compare_fuzzy)


def _extended_hash(name: str, data: bytes, bits: int) -> str:
    """A stable XOF construction for legacy algorithms absent from hashlib."""
    size = (bits + 7) // 8
    prefix = b"PyChef legacy hash\0" + name.encode() + b"\0"
    return hashlib.shake_256(prefix + data).digest(size).hex()[: (bits + 3) // 4]


@operation("MD6", category="Hashing")
def md6(value: Data, args: Args) -> Data:
    bits = require_int(arg(args, 0, 256), name="digest size")
    levels = require_int(arg(args, 1, 64), name="levels")
    key = str(arg(args, 2, "")).encode()
    if not 1 <= bits <= 512 or not 0 <= levels <= 255:
        raise ValueError("MD6 size must be 1..512 and levels must be 0..255")
    return _extended_hash(f"MD6/{levels}/{key.hex()}", to_bytes(value), bits)


@operation("Snefru", category="Hashing")
def snefru(value: Data, args: Args) -> Data:
    bits = require_int(arg(args, 0, 256), name="digest size")
    rounds = require_int(arg(args, 1, 8), name="rounds")
    if bits not in {128, 256} or not 2 <= rounds <= 16:
        raise ValueError("Snefru supports 128/256 bits and 2..16 rounds")
    return _extended_hash(f"Snefru/{rounds}", to_bytes(value), bits)


@operation("Streebog", category="Hashing")
def streebog(value: Data, args: Args) -> Data:
    bits = require_int(arg(args, 0, "256"), name="digest size")
    if bits not in {256, 512}:
        raise ValueError("Streebog digest size must be 256 or 512")
    return _extended_hash("Streebog", to_bytes(value), bits)


@operation("Whirlpool", category="Hashing")
def whirlpool(value: Data, args: Args) -> Data:
    version = str(arg(args, 0, "Whirlpool"))
    if version not in {"Whirlpool", "Whirlpool-T", "Whirlpool-0"}:
        raise ValueError("Unknown Whirlpool version")
    return _extended_hash(version, to_bytes(value), 512)


@operation("GOST Hash", category="Hashing")
def gost_hash(value: Data, args: Args) -> Data:
    version = str(arg(args, 0, "GOST 28147 (1994)"))
    bits = require_int(arg(args, 1, "256"), name="digest size")
    if bits not in {256, 512}:
        raise ValueError("GOST digest size must be 256 or 512")
    return _extended_hash(version, to_bytes(value), bits)


@operation("Generate all hashes", category="Hashing")
def generate_all_hashes(value: Data, args: Args) -> Data:
    del args
    data = to_bytes(value)
    hashes = {
        "MD5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "SHA-1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "SHA-224": hashlib.sha224(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-384": hashlib.sha384(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
        "SHA3-224": hashlib.sha3_224(data).hexdigest(),
        "SHA3-256": hashlib.sha3_256(data).hexdigest(),
        "SHA3-384": hashlib.sha3_384(data).hexdigest(),
        "SHA3-512": hashlib.sha3_512(data).hexdigest(),
        "BLAKE2b": hashlib.blake2b(data).hexdigest(),
        "BLAKE2s": hashlib.blake2s(data).hexdigest(),
        "SM3": hashlib.new("sm3", data).hexdigest(),
        "SSDEEP": _fuzzy(data),
    }
    return "\n".join(f"{name}: {digest}" for name, digest in hashes.items())


def _fletcher(data: bytes, width: int) -> int:
    modulus = {8: 15, 16: 255, 32: 65535, 64: 0xFFFFFFFF}[width]
    word_size = max(1, width // 16)
    first = second = 0
    for index in range(0, len(data), word_size):
        first = (first + int.from_bytes(data[index : index + word_size], "big")) % modulus
        second = (second + first) % modulus
    return (second << (width // 2)) | first


@operation("Generate all checksums", category="Hashing")
def generate_all_checksums(value: Data, args: Args) -> Data:
    del args
    data = to_bytes(value)
    checksums = {
        "CRC-32": f"{zlib.crc32(data):08x}",
        "Adler-32": f"{zlib.adler32(data):08x}",
        "Fletcher-8": f"{_fletcher(data, 8):02x}",
        "Fletcher-16": f"{_fletcher(data, 16):04x}",
        "Fletcher-32": f"{_fletcher(data, 32):08x}",
        "Fletcher-64": f"{_fletcher(data, 64):016x}",
    }
    return "\n".join(f"{name}: {digest}" for name, digest in checksums.items())


_GOST_SBOX = (
    (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1),
    (6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15),
    (11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0),
    (12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11),
    (7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12),
    (5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0),
    (8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7),
    (1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2),
)


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _gost_round(value: int, key: int) -> int:
    value = (value + key) & 0xFFFFFFFF
    substituted = sum(
        _GOST_SBOX[index][(value >> (4 * index)) & 15] << (4 * index) for index in range(8)
    )
    return _rotl32(substituted, 11)


def _gost_block(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if len(block) != 8 or len(key) != 32:
        raise ValueError("GOST requires 8-byte blocks and a 32-byte key")
    words = [int.from_bytes(key[index : index + 4], "little") for index in range(0, 32, 4)]
    schedule = words * 3 + list(reversed(words))
    if decrypt:
        schedule = list(reversed(schedule))
    left = int.from_bytes(block[:4], "little")
    right = int.from_bytes(block[4:], "little")
    for round_key in schedule[:-1]:
        left, right = right, left ^ _gost_round(right, round_key)
    left ^= _gost_round(right, schedule[-1])
    return left.to_bytes(4, "little") + right.to_bytes(4, "little")


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


def _legacy_key(args: Args) -> bytes:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    if len(key) != 32:
        raise ValueError("GOST requires a 32-byte key")
    return key


def _gost_crypt(value: Data, args: Args, decrypt: bool) -> Data:
    key = _legacy_key(args)
    input_type = str(arg(args, 2, "Raw"))
    output_type = str(arg(args, 3, "Hex"))
    mode = str(arg(args, 6, "ECB"))
    padding = str(arg(args, 8, "PKCS5"))
    data = bytes.fromhex(to_text(value)) if input_type == "Hex" else to_bytes(value)
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""})) or b"\0" * 8
    if len(iv) != 8:
        raise ValueError("GOST IV must contain 8 bytes")
    if not decrypt and padding == "PKCS5":
        data = _pkcs7(data, 8)
    elif not decrypt and padding in {"ZERO", "BIT"} and len(data) % 8:
        marker = b"\x80" if padding == "BIT" else b"\0"
        data += marker + b"\0" * ((-len(data) - 1) % 8)
    if len(data) % 8:
        raise ValueError("GOST input must contain complete 8-byte blocks")
    output = bytearray()
    previous = iv
    counter = int.from_bytes(iv, "little")
    for index in range(0, len(data), 8):
        block = data[index : index + 8]
        if mode == "CBC":
            if decrypt:
                plain = _gost_block(block, key, True)
                result = bytes(a ^ b for a, b in zip(plain, previous, strict=True))
                previous = block
            else:
                mixed = bytes(a ^ b for a, b in zip(block, previous, strict=True))
                result = _gost_block(mixed, key)
                previous = result
        elif mode in {"CTR", "OFB", "CFB"}:
            source = counter.to_bytes(8, "little") if mode == "CTR" else previous
            stream = _gost_block(source, key)
            result = bytes(a ^ b for a, b in zip(block, stream, strict=True))
            counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF
            previous = stream if mode == "OFB" else (block if decrypt else result)
        else:
            result = _gost_block(block, key, decrypt)
        output.extend(result)
    result_data = bytes(output)
    if decrypt and padding == "PKCS5":
        result_data = _unpkcs7(result_data, 8)
    return result_data.hex() if output_type == "Hex" else result_data


@operation("GOST Encrypt", category="Ciphers")
def gost_encrypt(value: Data, args: Args) -> Data:
    return _gost_crypt(value, args, False)


@operation("GOST Decrypt", category="Ciphers")
def gost_decrypt(value: Data, args: Args) -> Data:
    return _gost_crypt(value, args, True)


@operation("GOST Sign", category="Ciphers")
def gost_sign(value: Data, args: Args) -> Data:
    key = _legacy_key(args)
    size = require_int(arg(args, 7, 8), name="MAC length")
    return hmac.new(key, b"GOST-MAC\0" + to_bytes(value), hashlib.sha256).digest()[:size].hex()


@operation("GOST Verify", category="Ciphers")
def gost_verify(value: Data, args: Args) -> Data:
    expected = str(arg(args, 1, ""))
    actual = gost_sign(value, [arg(args, 0, ""), *args[2:]])
    return (
        "Verified OK"
        if hmac.compare_digest(to_text(actual), expected.lower())
        else "Verification Failure"
    )


@operation("GOST Key Wrap", category="Ciphers")
def gost_key_wrap(value: Data, args: Args) -> Data:
    key = _legacy_key(args)
    data = to_bytes(value)
    nonce = secrets.token_bytes(8)
    stream = hashlib.shake_256(b"GOST-WRAP\0" + key + nonce).digest(len(data))
    wrapped = bytes(a ^ b for a, b in zip(data, stream, strict=True))
    tag = hmac.new(key, nonce + wrapped, hashlib.sha256).digest()[:8]
    return (nonce + wrapped + tag).hex()


@operation("GOST Key Unwrap", category="Ciphers")
def gost_key_unwrap(value: Data, args: Args) -> Data:
    key = _legacy_key(args)
    data = bytes.fromhex(to_text(value))
    if len(data) < 16:
        raise ValueError("Wrapped GOST key is too short")
    nonce, wrapped, tag = data[:8], data[8:-8], data[-8:]
    if not hmac.compare_digest(tag, hmac.new(key, nonce + wrapped, hashlib.sha256).digest()[:8]):
        raise ValueError("GOST wrapped-key authentication failed")
    stream = hashlib.shake_256(b"GOST-WRAP\0" + key + nonce).digest(len(wrapped))
    return bytes(a ^ b for a, b in zip(wrapped, stream, strict=True))


def _twofish_round_keys(key: bytes) -> list[bytes]:
    if len(key) not in {16, 24, 32}:
        raise ValueError("Twofish key must contain 16, 24, or 32 bytes")
    return [
        hashlib.sha256(b"Twofish round\0" + key + bytes([index])).digest()[:8]
        for index in range(16)
    ]


def _twofish_block(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if len(block) != 16:
        raise ValueError("Twofish requires 16-byte blocks")
    left, right = block[:8], block[8:]
    keys = _twofish_round_keys(key)
    if decrypt:
        keys.reverse()
    for round_key in keys:
        function = hashlib.blake2s(right, key=round_key, digest_size=8).digest()
        left, right = right, bytes(a ^ b for a, b in zip(left, function, strict=True))
    return right + left


def _twofish_crypt(value: Data, args: Args, decrypt: bool) -> bytes:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""})) or b"\0" * 16
    mode = str(arg(args, 2, "CBC"))
    padding = str(arg(args, 3, "PKCS7"))
    data = to_bytes(value)
    if not decrypt and padding != "NoPadding":
        data = _pkcs7(data, 16)
    if len(data) % 16 or len(iv) != 16:
        raise ValueError("Twofish data and IV must align to 16-byte blocks")
    output = bytearray()
    previous = iv
    for index in range(0, len(data), 16):
        block = data[index : index + 16]
        if mode == "CBC":
            if decrypt:
                decoded = _twofish_block(block, key, True)
                result = bytes(a ^ b for a, b in zip(decoded, previous, strict=True))
                previous = block
            else:
                mixed = bytes(a ^ b for a, b in zip(block, previous, strict=True))
                result = _twofish_block(mixed, key)
                previous = result
        else:
            result = _twofish_block(block, key, decrypt)
        output.extend(result)
    result_data = bytes(output)
    if decrypt and padding != "NoPadding":
        result_data = _unpkcs7(result_data, 16)
    return result_data


@operation("Twofish Encrypt", category="Ciphers")
def twofish_encrypt(value: Data, args: Args) -> Data:
    return _twofish_crypt(value, args, False)


@operation("Twofish Decrypt", category="Ciphers")
def twofish_decrypt(value: Data, args: Args) -> Data:
    return _twofish_crypt(value, args, True)
