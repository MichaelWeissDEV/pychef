"""Small, byte-exact helpers for exploits, CTFs, and binary protocols."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable, Sequence
from typing import Any, Literal

from ._bytes import xor_repeating
from .types import Data, to_bytes

BytesLike = bytes | bytearray | memoryview


# The AES implementation is imported on first use so ``import pychef`` stays light.
def _require_key(key: bytes) -> None:
    from .operations.aes import _require_key as implementation

    implementation(key)


def _gcm(*args: Any, **kwargs: Any) -> Any:
    from .operations.aes import _gcm as implementation

    return implementation(*args, **kwargs)


def _block_mode(*args: Any, **kwargs: Any) -> Any:
    from .operations.aes import _block_mode as implementation

    return implementation(*args, **kwargs)


def decode_bytes(value: str | BytesLike, *, format: str = "raw") -> bytes:
    """Decode an explicitly formatted value to bytes.

    Supported formats are ``raw``/``utf8``, ``hex``, ``base64``, and
    ``latin1``. Bytes in raw mode are returned without a copy where possible.
    """
    normalized = format.lower().replace("-", "").replace("_", "")
    if normalized in {"raw", "utf8", "utf"}:
        return value.encode("utf-8") if isinstance(value, str) else bytes(value)
    text = value if isinstance(value, str) else bytes(value).decode("ascii")
    if normalized == "hex":
        return bytes.fromhex(text)
    if normalized in {"base64", "b64"}:
        return base64.b64decode(text, validate=True)
    if normalized in {"latin1", "iso88591"}:
        return text.encode("latin-1")
    raise ValueError(f"unsupported byte format: {format}")


def encode_bytes(value: Data | BytesLike, *, format: str = "raw") -> bytes | str:
    """Encode bytes as raw bytes, UTF-8 text, hex, base64, or Latin-1."""
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    normalized = format.lower().replace("-", "").replace("_", "")
    if normalized == "raw":
        return data
    if normalized in {"utf8", "utf"}:
        return data.decode("utf-8")
    if normalized == "hex":
        return data.hex()
    if normalized in {"base64", "b64"}:
        return base64.b64encode(data).decode("ascii")
    if normalized in {"latin1", "iso88591"}:
        return data.decode("latin-1")
    raise ValueError(f"unsupported byte format: {format}")


def _byte_order(endian: str) -> Literal["little", "big"]:
    normalized = endian.lower()
    if normalized in {"little", "le", "l"}:
        return "little"
    if normalized in {"big", "be", "b", "network"}:
        return "big"
    raise ValueError("endian must be 'little'/'le' or 'big'/'be'")


def pack(value: int, bits: int = 32, *, endian: str = "little", signed: bool = False) -> bytes:
    """Pack one integer with an explicit width and byte order."""
    if bits < 8 or bits % 8:
        raise ValueError("bits must be a positive multiple of 8")
    try:
        return int(value).to_bytes(bits // 8, _byte_order(endian), signed=signed)
    except OverflowError as exc:
        kind = "signed" if signed else "unsigned"
        raise ValueError(f"{value} does not fit in a {bits}-bit {kind} integer") from exc


def unpack(
    value: Data | BytesLike,
    bits: int = 32,
    *,
    endian: str = "little",
    signed: bool = False,
    offset: int = 0,
) -> int:
    """Unpack one integer at *offset* and reject truncated input."""
    if bits < 8 or bits % 8:
        raise ValueError("bits must be a positive multiple of 8")
    if offset < 0:
        raise ValueError("offset must not be negative")
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    size = bits // 8
    selected = data[offset : offset + size]
    if len(selected) != size:
        raise ValueError(f"need {size} bytes at offset {offset}, got {len(selected)}")
    return int.from_bytes(selected, _byte_order(endian), signed=signed)


def p8(value: int, *, signed: bool = False) -> bytes:
    return pack(value, 8, signed=signed)


def p16(value: int, *, endian: str = "little", signed: bool = False) -> bytes:
    return pack(value, 16, endian=endian, signed=signed)


def p32(value: int, *, endian: str = "little", signed: bool = False) -> bytes:
    return pack(value, 32, endian=endian, signed=signed)


def p64(value: int, *, endian: str = "little", signed: bool = False) -> bytes:
    return pack(value, 64, endian=endian, signed=signed)


def u8(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return unpack(value, 8, offset=offset, signed=signed)


def u16(
    value: Data | BytesLike,
    *,
    endian: str = "little",
    offset: int = 0,
    signed: bool = False,
) -> int:
    return unpack(value, 16, endian=endian, offset=offset, signed=signed)


def u32(
    value: Data | BytesLike,
    *,
    endian: str = "little",
    offset: int = 0,
    signed: bool = False,
) -> int:
    return unpack(value, 32, endian=endian, offset=offset, signed=signed)


def u64(
    value: Data | BytesLike,
    *,
    endian: str = "little",
    offset: int = 0,
    signed: bool = False,
) -> int:
    return unpack(value, 64, endian=endian, offset=offset, signed=signed)


def p16be(value: int, *, signed: bool = False) -> bytes:
    return p16(value, endian="big", signed=signed)


def p16le(value: int, *, signed: bool = False) -> bytes:
    return p16(value, endian="little", signed=signed)


def p32be(value: int, *, signed: bool = False) -> bytes:
    return p32(value, endian="big", signed=signed)


def p32le(value: int, *, signed: bool = False) -> bytes:
    return p32(value, endian="little", signed=signed)


def p64be(value: int, *, signed: bool = False) -> bytes:
    return p64(value, endian="big", signed=signed)


def p64le(value: int, *, signed: bool = False) -> bytes:
    return p64(value, endian="little", signed=signed)


def u16be(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return u16(value, endian="big", offset=offset, signed=signed)


def u16le(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return u16(value, endian="little", offset=offset, signed=signed)


def u32be(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return u32(value, endian="big", offset=offset, signed=signed)


def u32le(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return u32(value, endian="little", offset=offset, signed=signed)


def u64be(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return u64(value, endian="big", offset=offset, signed=signed)


def u64le(value: Data | BytesLike, *, offset: int = 0, signed: bool = False) -> int:
    return u64(value, endian="little", offset=offset, signed=signed)


def flat(
    *values: Any,
    word_size: int = 32,
    endian: str = "little",
    signed: bool = False,
    encoding: str = "utf-8",
) -> bytes:
    """Flatten integers, byte strings, text, and nested sequences to bytes."""
    output = bytearray()

    def append(value: Any) -> None:
        if isinstance(value, int):
            output.extend(pack(value, word_size, endian=endian, signed=signed))
        elif isinstance(value, str):
            output.extend(value.encode(encoding))
        elif isinstance(value, (bytes, bytearray, memoryview)):
            output.extend(value)
        elif isinstance(value, Sequence):
            for item in value:
                append(item)
        else:
            raise TypeError(f"cannot flatten {type(value).__name__}")

    for item in values:
        append(item)
    return bytes(output)


def chunks(value: Data | BytesLike, size: int, *, drop_incomplete: bool = False) -> tuple[Any, ...]:
    """Split bytes or text into fixed-size chunks while preserving its type."""
    if size < 1:
        raise ValueError("size must be positive")
    result = tuple(value[position : position + size] for position in range(0, len(value), size))
    if drop_incomplete and result and len(result[-1]) != size:
        return result[:-1]
    return result


def swap_endian(
    value: Data | BytesLike,
    word_size: int = 4,
    *,
    strict: bool = True,
) -> bytes:
    """Reverse the byte order independently in each fixed-width word."""
    if word_size < 1:
        raise ValueError("word_size must be positive")
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    if strict and len(data) % word_size:
        raise ValueError("input length must be divisible by word_size")
    return b"".join(part[::-1] for part in chunks(data, word_size))


def xor_bytes(
    value: Data | BytesLike,
    key: Data | BytesLike,
    *,
    repeat: bool = True,
) -> bytes:
    """XOR a byte string with a key, repeating the key by default."""
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    key_bytes = to_bytes(key) if isinstance(key, (str, bytes)) else bytes(key)
    if not key_bytes:
        raise ValueError("XOR key must not be empty")
    if not repeat and len(key_bytes) < len(data):
        raise ValueError("XOR key is shorter than the input")
    return xor_repeating(data, key_bytes)


def rol(value: int, amount: int, bits: int = 32) -> int:
    """Rotate an integer left inside a fixed-width word."""
    if bits < 1:
        raise ValueError("bits must be positive")
    amount %= bits
    mask = (1 << bits) - 1
    value &= mask
    return ((value << amount) | (value >> ((bits - amount) % bits))) & mask


def ror(value: int, amount: int, bits: int = 32) -> int:
    """Rotate an integer right inside a fixed-width word."""
    return rol(value, -amount, bits)


def digest(
    value: Data | BytesLike,
    *,
    algorithm: str = "sha256",
    output: str = "hex",
) -> bytes | str:
    """Calculate any hash provided by ``hashlib`` with a predictable output."""
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    requested = algorithm.strip().lower()
    candidates = (requested, requested.replace("-", "_"), requested.replace("-", ""))
    for candidate in dict.fromkeys(candidates):
        try:
            result = hashlib.new(candidate, data).digest()
            break
        except ValueError:
            continue
    else:
        raise ValueError(f"unsupported hash algorithm: {algorithm}")
    normalized = output.lower()
    if normalized in {"raw", "bytes"}:
        return result
    if normalized == "hex":
        return result.hex()
    if normalized in {"base64", "b64"}:
        return base64.b64encode(result).decode("ascii")
    raise ValueError(f"unsupported digest output: {output}")


def digests(
    value: Data | BytesLike,
    algorithms: Iterable[str] = ("md5", "sha1", "sha256", "sha512"),
) -> dict[str, str]:
    """Calculate several hexadecimal hashes in one call."""
    return {algorithm: str(digest(value, algorithm=algorithm)) for algorithm in algorithms}


def md5(value: Data | BytesLike) -> str:
    """Return the MD5 digest as lowercase hexadecimal text (same as ``pychef.ops.md5``)."""
    return str(digest(value, algorithm="md5"))


def sha1(value: Data | BytesLike) -> str:
    """Return the SHA-1 digest as lowercase hexadecimal text (same as ``pychef.ops.sha1``)."""
    return str(digest(value, algorithm="sha1"))


def sha256(value: Data | BytesLike) -> str:
    """Return the SHA-256 digest as lowercase hexadecimal text (same as ``pychef.ops.sha256``)."""
    return str(digest(value, algorithm="sha256"))


def sha512(value: Data | BytesLike) -> str:
    """Return the SHA-512 digest as lowercase hexadecimal text (same as ``pychef.ops.sha512``)."""
    return str(digest(value, algorithm="sha512"))


def hexdump(value: Data | BytesLike, *, width: int = 16, start: int = 0) -> str:
    """Return a compact offset/hex/ASCII dump suitable for terminals."""
    if width < 1:
        raise ValueError("width must be positive")
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    offset_width = max(8, len(f"{start + len(data):x}"))
    lines = []
    for position in range(0, len(data), width):
        block = data[position : position + width]
        hexadecimal = " ".join(f"{byte:02x}" for byte in block)
        printable = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in block)
        lines.append(
            f"{start + position:0{offset_width}x}  {hexadecimal:<{width * 3 - 1}}  |{printable}|"
        )
    return "\n".join(lines)


def _normalize_aes_mode(mode: str) -> str:
    normalized = mode.upper().replace("-", "").replace("_", "")
    aliases = {"AESGCM": "GCM", "AESCBC": "CBC", "AESECB": "ECB"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"CBC", "ECB", "CFB", "OFB", "CTR", "GCM"}:
        raise ValueError(f"unsupported AES mode: {mode}")
    return normalized


def _aes_material(
    key: str | BytesLike,
    iv: str | BytesLike | None,
    *,
    mode: str,
    key_format: str,
    iv_format: str,
) -> tuple[bytes, bytes]:
    key_bytes = decode_bytes(key, format=key_format)
    _require_key(key_bytes)
    if mode == "ECB":
        iv_supplied = (
            iv != "" if isinstance(iv, str) else bool(bytes(iv)) if iv is not None else False
        )
        if iv_supplied:
            raise ValueError("AES-ECB does not use an IV")
        return key_bytes, b""
    if iv is None:
        raise ValueError(f"AES-{mode} requires an explicit IV/nonce")
    iv_bytes = decode_bytes(iv, format=iv_format)
    if mode != "GCM" and len(iv_bytes) != 16:
        raise ValueError(f"AES-{mode} requires a 16-byte IV")
    return key_bytes, iv_bytes


def aes_gcm_encrypt(
    value: Data | BytesLike,
    key: str | BytesLike,
    *,
    iv: str | BytesLike,
    aad: Data | BytesLike = b"",
    key_format: str = "raw",
    iv_format: str = "raw",
) -> tuple[bytes, bytes]:
    """Encrypt with AES-GCM and return ``(ciphertext, 16-byte tag)``."""
    key_bytes, iv_bytes = _aes_material(
        key, iv, mode="GCM", key_format=key_format, iv_format=iv_format
    )
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    aad_bytes = to_bytes(aad) if isinstance(aad, (str, bytes)) else bytes(aad)
    return _gcm(data, key_bytes, iv_bytes, aad_bytes, decrypting=False)


def aes_gcm_decrypt(
    value: Data | BytesLike,
    key: str | BytesLike,
    *,
    iv: str | BytesLike,
    tag: str | BytesLike,
    aad: Data | BytesLike = b"",
    key_format: str = "raw",
    iv_format: str = "raw",
    tag_format: str = "raw",
) -> bytes:
    """Authenticate and decrypt an AES-GCM ciphertext."""
    key_bytes, iv_bytes = _aes_material(
        key, iv, mode="GCM", key_format=key_format, iv_format=iv_format
    )
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    aad_bytes = to_bytes(aad) if isinstance(aad, (str, bytes)) else bytes(aad)
    tag_bytes = decode_bytes(tag, format=tag_format)
    result, _tag = _gcm(
        data,
        key_bytes,
        iv_bytes,
        aad_bytes,
        decrypting=True,
        expected_tag=tag_bytes,
    )
    return result


def aes_encrypt(
    value: Data | BytesLike,
    key: str | BytesLike,
    *,
    mode: str = "CBC",
    iv: str | BytesLike | None = None,
    padding: str = "pkcs7",
    aad: Data | BytesLike = b"",
    key_format: str = "raw",
    iv_format: str = "raw",
    append_tag: bool = True,
) -> bytes:
    """Encrypt bytes with AES; GCM appends its tag by default."""
    normalized_mode = _normalize_aes_mode(mode)
    key_bytes, iv_bytes = _aes_material(
        key,
        iv,
        mode=normalized_mode,
        key_format=key_format,
        iv_format=iv_format,
    )
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    normalized_padding = padding.lower().replace("-", "")
    if normalized_padding not in {"pkcs7", "none", "nopadding"}:
        raise ValueError("padding must be 'pkcs7' or 'none'")
    if normalized_mode == "GCM":
        aad_bytes = to_bytes(aad) if isinstance(aad, (str, bytes)) else bytes(aad)
        ciphertext, tag = _gcm(data, key_bytes, iv_bytes, aad_bytes, decrypting=False)
        return ciphertext + tag if append_tag else ciphertext
    return _block_mode(
        data,
        key_bytes,
        iv_bytes,
        normalized_mode,
        decrypting=False,
        no_padding=normalized_padding != "pkcs7",
    )


def aes_decrypt(
    value: Data | BytesLike,
    key: str | BytesLike,
    *,
    mode: str = "CBC",
    iv: str | BytesLike | None = None,
    padding: str = "pkcs7",
    aad: Data | BytesLike = b"",
    tag: str | BytesLike | None = None,
    key_format: str = "raw",
    iv_format: str = "raw",
    tag_format: str = "raw",
) -> bytes:
    """Decrypt AES bytes; GCM reads an appended tag when *tag* is omitted."""
    normalized_mode = _normalize_aes_mode(mode)
    key_bytes, iv_bytes = _aes_material(
        key,
        iv,
        mode=normalized_mode,
        key_format=key_format,
        iv_format=iv_format,
    )
    data = to_bytes(value) if isinstance(value, (str, bytes)) else bytes(value)
    normalized_padding = padding.lower().replace("-", "")
    if normalized_padding not in {"pkcs7", "none", "nopadding"}:
        raise ValueError("padding must be 'pkcs7' or 'none'")
    if normalized_mode == "GCM":
        if tag is None:
            if len(data) < 16:
                raise ValueError("AES-GCM input is too short to contain a 16-byte tag")
            data, tag_bytes = data[:-16], data[-16:]
        else:
            tag_bytes = decode_bytes(tag, format=tag_format)
        aad_bytes = to_bytes(aad) if isinstance(aad, (str, bytes)) else bytes(aad)
        result, _actual_tag = _gcm(
            data,
            key_bytes,
            iv_bytes,
            aad_bytes,
            decrypting=True,
            expected_tag=tag_bytes,
        )
        return result
    return _block_mode(
        data,
        key_bytes,
        iv_bytes,
        normalized_mode,
        decrypting=True,
        no_padding=normalized_padding != "pkcs7",
    )


def cyclic(
    length: int,
    *,
    alphabet: bytes = b"abcdefghijklmnopqrstuvwxyz",
    n: int = 4,
) -> bytes:
    """Generate a deterministic de Bruijn pattern for offset discovery."""
    if length < 0:
        raise ValueError("length must not be negative")
    if n < 1 or not alphabet or len(set(alphabet)) != len(alphabet):
        raise ValueError("n and alphabet must define a non-empty unique alphabet")
    maximum = len(alphabet) ** n
    if length > maximum:
        raise ValueError(f"requested pattern exceeds the {maximum}-byte unique cycle")
    state = [0] * (n + 1)
    output = bytearray()

    def generate(position: int, period: int) -> None:
        if len(output) >= length:
            return
        if position > n:
            if n % period == 0:
                output.extend(alphabet[state[index]] for index in range(1, period + 1))
            return
        state[position] = state[position - period]
        generate(position + 1, period)
        for index in range(state[position - period] + 1, len(alphabet)):
            state[position] = index
            generate(position + 1, position)

    generate(1, 1)
    return bytes(output[:length])


def cyclic_find(
    subsequence: int | Data | BytesLike,
    *,
    alphabet: bytes = b"abcdefghijklmnopqrstuvwxyz",
    n: int = 4,
    endian: str = "little",
) -> int:
    """Return a pattern offset or ``-1`` when the subsequence is absent."""
    if isinstance(subsequence, int):
        needle = pack(subsequence, n * 8, endian=endian)
    elif isinstance(subsequence, (str, bytes)):
        needle = to_bytes(subsequence)
    else:
        needle = bytes(subsequence)
    if len(needle) > n:
        needle = needle[:n]
    return cyclic(len(alphabet) ** n, alphabet=alphabet, n=n).find(needle)


__all__ = [
    "BytesLike",
    "aes_decrypt",
    "aes_encrypt",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "chunks",
    "cyclic",
    "cyclic_find",
    "decode_bytes",
    "digest",
    "digests",
    "encode_bytes",
    "flat",
    "hexdump",
    "md5",
    "p8",
    "p16",
    "p16be",
    "p16le",
    "p32",
    "p32be",
    "p32le",
    "p64",
    "p64be",
    "p64le",
    "pack",
    "rol",
    "ror",
    "sha1",
    "sha256",
    "sha512",
    "swap_endian",
    "u8",
    "u16",
    "u16be",
    "u16le",
    "u32",
    "u32be",
    "u32le",
    "u64",
    "u64be",
    "u64le",
    "unpack",
    "xor_bytes",
]
