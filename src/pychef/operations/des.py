"""Dependency-free DES, Triple DES, and LAN Manager hashing."""

from __future__ import annotations

from functools import lru_cache

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg
from .modern_ciphers import _formatted_input, _formatted_output, _toggle_bytes

_IP = (
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    64,
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
)
_FP = (
    40,
    8,
    48,
    16,
    56,
    24,
    64,
    32,
    39,
    7,
    47,
    15,
    55,
    23,
    63,
    31,
    38,
    6,
    46,
    14,
    54,
    22,
    62,
    30,
    37,
    5,
    45,
    13,
    53,
    21,
    61,
    29,
    36,
    4,
    44,
    12,
    52,
    20,
    60,
    28,
    35,
    3,
    43,
    11,
    51,
    19,
    59,
    27,
    34,
    2,
    42,
    10,
    50,
    18,
    58,
    26,
    33,
    1,
    41,
    9,
    49,
    17,
    57,
    25,
)
_EXPANSION = (
    32,
    1,
    2,
    3,
    4,
    5,
    4,
    5,
    6,
    7,
    8,
    9,
    8,
    9,
    10,
    11,
    12,
    13,
    12,
    13,
    14,
    15,
    16,
    17,
    16,
    17,
    18,
    19,
    20,
    21,
    20,
    21,
    22,
    23,
    24,
    25,
    24,
    25,
    26,
    27,
    28,
    29,
    28,
    29,
    30,
    31,
    32,
    1,
)
_P = (
    16,
    7,
    20,
    21,
    29,
    12,
    28,
    17,
    1,
    15,
    23,
    26,
    5,
    18,
    31,
    10,
    2,
    8,
    24,
    14,
    32,
    27,
    3,
    9,
    19,
    13,
    30,
    6,
    22,
    11,
    4,
    25,
)
_PC1 = (
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    60,
    52,
    44,
    36,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    28,
    20,
    12,
    4,
)
_PC2 = (
    14,
    17,
    11,
    24,
    1,
    5,
    3,
    28,
    15,
    6,
    21,
    10,
    23,
    19,
    12,
    4,
    26,
    8,
    16,
    7,
    27,
    20,
    13,
    2,
    41,
    52,
    31,
    37,
    47,
    55,
    30,
    40,
    51,
    45,
    33,
    48,
    44,
    49,
    39,
    56,
    34,
    53,
    46,
    42,
    50,
    36,
    29,
    32,
)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_S_BOXES = (
    (
        14,
        4,
        13,
        1,
        2,
        15,
        11,
        8,
        3,
        10,
        6,
        12,
        5,
        9,
        0,
        7,
        0,
        15,
        7,
        4,
        14,
        2,
        13,
        1,
        10,
        6,
        12,
        11,
        9,
        5,
        3,
        8,
        4,
        1,
        14,
        8,
        13,
        6,
        2,
        11,
        15,
        12,
        9,
        7,
        3,
        10,
        5,
        0,
        15,
        12,
        8,
        2,
        4,
        9,
        1,
        7,
        5,
        11,
        3,
        14,
        10,
        0,
        6,
        13,
    ),
    (
        15,
        1,
        8,
        14,
        6,
        11,
        3,
        4,
        9,
        7,
        2,
        13,
        12,
        0,
        5,
        10,
        3,
        13,
        4,
        7,
        15,
        2,
        8,
        14,
        12,
        0,
        1,
        10,
        6,
        9,
        11,
        5,
        0,
        14,
        7,
        11,
        10,
        4,
        13,
        1,
        5,
        8,
        12,
        6,
        9,
        3,
        2,
        15,
        13,
        8,
        10,
        1,
        3,
        15,
        4,
        2,
        11,
        6,
        7,
        12,
        0,
        5,
        14,
        9,
    ),
    (
        10,
        0,
        9,
        14,
        6,
        3,
        15,
        5,
        1,
        13,
        12,
        7,
        11,
        4,
        2,
        8,
        13,
        7,
        0,
        9,
        3,
        4,
        6,
        10,
        2,
        8,
        5,
        14,
        12,
        11,
        15,
        1,
        13,
        6,
        4,
        9,
        8,
        15,
        3,
        0,
        11,
        1,
        2,
        12,
        5,
        10,
        14,
        7,
        1,
        10,
        13,
        0,
        6,
        9,
        8,
        7,
        4,
        15,
        14,
        3,
        11,
        5,
        2,
        12,
    ),
    (
        7,
        13,
        14,
        3,
        0,
        6,
        9,
        10,
        1,
        2,
        8,
        5,
        11,
        12,
        4,
        15,
        13,
        8,
        11,
        5,
        6,
        15,
        0,
        3,
        4,
        7,
        2,
        12,
        1,
        10,
        14,
        9,
        10,
        6,
        9,
        0,
        12,
        11,
        7,
        13,
        15,
        1,
        3,
        14,
        5,
        2,
        8,
        4,
        3,
        15,
        0,
        6,
        10,
        1,
        13,
        8,
        9,
        4,
        5,
        11,
        12,
        7,
        2,
        14,
    ),
    (
        2,
        12,
        4,
        1,
        7,
        10,
        11,
        6,
        8,
        5,
        3,
        15,
        13,
        0,
        14,
        9,
        14,
        11,
        2,
        12,
        4,
        7,
        13,
        1,
        5,
        0,
        15,
        10,
        3,
        9,
        8,
        6,
        4,
        2,
        1,
        11,
        10,
        13,
        7,
        8,
        15,
        9,
        12,
        5,
        6,
        3,
        0,
        14,
        11,
        8,
        12,
        7,
        1,
        14,
        2,
        13,
        6,
        15,
        0,
        9,
        10,
        4,
        5,
        3,
    ),
    (
        12,
        1,
        10,
        15,
        9,
        2,
        6,
        8,
        0,
        13,
        3,
        4,
        14,
        7,
        5,
        11,
        10,
        15,
        4,
        2,
        7,
        12,
        9,
        5,
        6,
        1,
        13,
        14,
        0,
        11,
        3,
        8,
        9,
        14,
        15,
        5,
        2,
        8,
        12,
        3,
        7,
        0,
        4,
        10,
        1,
        13,
        11,
        6,
        4,
        3,
        2,
        12,
        9,
        5,
        15,
        10,
        11,
        14,
        1,
        7,
        6,
        0,
        8,
        13,
    ),
    (
        4,
        11,
        2,
        14,
        15,
        0,
        8,
        13,
        3,
        12,
        9,
        7,
        5,
        10,
        6,
        1,
        13,
        0,
        11,
        7,
        4,
        9,
        1,
        10,
        14,
        3,
        5,
        12,
        2,
        15,
        8,
        6,
        1,
        4,
        11,
        13,
        12,
        3,
        7,
        14,
        10,
        15,
        6,
        8,
        0,
        5,
        9,
        2,
        6,
        11,
        13,
        8,
        1,
        4,
        10,
        7,
        9,
        5,
        0,
        15,
        14,
        2,
        3,
        12,
    ),
    (
        13,
        2,
        8,
        4,
        6,
        15,
        11,
        1,
        10,
        9,
        3,
        14,
        5,
        0,
        12,
        7,
        1,
        15,
        13,
        8,
        10,
        3,
        7,
        4,
        12,
        5,
        6,
        11,
        0,
        14,
        9,
        2,
        7,
        11,
        4,
        1,
        9,
        12,
        14,
        2,
        0,
        6,
        10,
        13,
        15,
        3,
        5,
        8,
        2,
        1,
        14,
        7,
        4,
        10,
        8,
        13,
        15,
        12,
        9,
        0,
        3,
        5,
        6,
        11,
    ),
)


def _permute(value: int, table: tuple[int, ...], input_bits: int) -> int:
    output = 0
    for position in table:
        output = (output << 1) | ((value >> (input_bits - position)) & 1)
    return output


@lru_cache(maxsize=256)
def _subkeys(key: bytes) -> tuple[int, ...]:
    if len(key) != 8:
        raise ValueError("DES keys must be 8 bytes")
    permuted = _permute(int.from_bytes(key, "big"), _PC1, 64)
    left, right = permuted >> 28, permuted & 0x0FFFFFFF
    output = []
    for shift in _SHIFTS:
        left = ((left << shift) | (left >> (28 - shift))) & 0x0FFFFFFF
        right = ((right << shift) | (right >> (28 - shift))) & 0x0FFFFFFF
        output.append(_permute((left << 28) | right, _PC2, 56))
    return tuple(output)


def _feistel(value: int, subkey: int) -> int:
    expanded = _permute(value, _EXPANSION, 32) ^ subkey
    substituted = 0
    for index, s_box in enumerate(_S_BOXES):
        chunk = (expanded >> (42 - 6 * index)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 1)
        column = (chunk >> 1) & 0xF
        substituted = (substituted << 4) | s_box[row * 16 + column]
    return _permute(substituted, _P, 32)


def _des_block(block: bytes, key: bytes, *, decrypting: bool = False) -> bytes:
    if len(block) != 8:
        raise ValueError("DES blocks must be 8 bytes")
    permuted = _permute(int.from_bytes(block, "big"), _IP, 64)
    left, right = permuted >> 32, permuted & 0xFFFFFFFF
    keys = reversed(_subkeys(key)) if decrypting else _subkeys(key)
    for subkey in keys:
        left, right = right, left ^ _feistel(right, subkey)
    result = _permute((right << 32) | left, _FP, 64)
    return result.to_bytes(8, "big")


def _triple_des_block(block: bytes, key: bytes, *, decrypting: bool = False) -> bytes:
    first, second, third = key[:8], key[8:16], key[16:24]
    if decrypting:
        block = _des_block(block, third, decrypting=True)
        block = _des_block(block, second)
        return _des_block(block, first, decrypting=True)
    block = _des_block(block, first)
    block = _des_block(block, second, decrypting=True)
    return _des_block(block, third)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _crypt_mode(
    data: bytes,
    key: bytes,
    iv: bytes,
    mode: str,
    *,
    decrypting: bool,
    triple: bool,
    no_padding: bool,
) -> bytes:
    def encrypt(block: bytes) -> bytes:
        return _triple_des_block(block, key) if triple else _des_block(block, key)

    def decrypt(block: bytes) -> bytes:
        if triple:
            return _triple_des_block(block, key, decrypting=True)
        return _des_block(block, key, decrypting=True)

    if mode in {"CBC", "ECB"}:
        if decrypting:
            if len(data) % 8:
                raise ValueError("ciphertext length must be a multiple of 8 bytes")
        else:
            count = 8 - len(data) % 8
            data += bytes([count]) * count
    output = bytearray()
    feedback = iv
    for position in range(0, len(data), 8):
        block = data[position : position + 8]
        if mode == "ECB":
            output.extend(decrypt(block) if decrypting else encrypt(block))
        elif mode == "CBC":
            if decrypting:
                output.extend(_xor(decrypt(block), feedback))
                feedback = block
            else:
                feedback = encrypt(_xor(block, feedback))
                output.extend(feedback)
        elif mode == "CFB":
            transformed = _xor(block, encrypt(feedback)[: len(block)])
            output.extend(transformed)
            feedback = block if decrypting else transformed
        elif mode == "OFB":
            feedback = encrypt(feedback)
            output.extend(_xor(block, feedback[: len(block)]))
        elif mode == "CTR":
            output.extend(_xor(block, encrypt(feedback)[: len(block)]))
            counter = (int.from_bytes(feedback[-4:], "big") + 1) & 0xFFFFFFFF
            feedback = feedback[:-4] + counter.to_bytes(4, "big")
        else:
            raise ValueError(f"invalid DES mode: {mode}")
    result = bytes(output)
    if decrypting and mode in {"CBC", "ECB"} and not no_padding:
        if not result:
            raise ValueError("Unable to decrypt input with these parameters.")
        count = result[-1]
        if not 1 <= count <= 8 or result[-count:] != bytes([count]) * count:
            raise ValueError("Unable to decrypt input with these parameters.")
        result = result[:-count]
    return result


def _des(value: Data, args: Args, *, decrypting: bool, triple: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    mode_arg = str(arg(args, 2, "CBC"))
    mode = mode_arg.split("/", 1)[0]
    no_padding = mode_arg.endswith("NoPadding")
    input_format = str(arg(args, 3, "Hex" if decrypting else "Raw"))
    output_format = str(arg(args, 4, "Raw" if decrypting else "Hex"))
    valid_lengths = {16, 24} if triple else {8}
    if len(key) not in valid_lengths:
        name = "Triple DES" if triple else "DES"
        required = "24 bytes (192 bits)" if triple else "8 bytes (64 bits)"
        raise ValueError(
            f"Invalid key length: {len(key)} bytes\n\n{name} uses a key length of {required}."
        )
    if triple and len(key) == 16:
        key += key[:8]
    if mode != "ECB" and len(iv) != 8:
        name = "Triple DES" if triple else "DES"
        raise ValueError(
            f"Invalid IV length: {len(iv)} bytes\n\n"
            f"{name} uses an IV length of 8 bytes (64 bits).\n"
            "Make sure you have specified the type correctly (e.g. Hex vs UTF8)."
        )
    data = _formatted_input(value, input_format)
    result = _crypt_mode(
        data,
        key,
        iv,
        mode,
        decrypting=decrypting,
        triple=triple,
        no_padding=no_padding,
    )
    return _formatted_output(result, output_format)


@operation("DES Encrypt", category="Ciphers")
def des_encrypt(value: Data, args: Args) -> Data:
    return _des(value, args, decrypting=False, triple=False)


@operation("DES Decrypt", category="Ciphers")
def des_decrypt(value: Data, args: Args) -> Data:
    return _des(value, args, decrypting=True, triple=False)


@operation("Triple DES Encrypt", category="Ciphers")
def triple_des_encrypt(value: Data, args: Args) -> Data:
    return _des(value, args, decrypting=False, triple=True)


@operation("Triple DES Decrypt", category="Ciphers")
def triple_des_decrypt(value: Data, args: Args) -> Data:
    return _des(value, args, decrypting=True, triple=True)


def _lm_des_key(key: bytes) -> bytes:
    value = int.from_bytes(key, "big")
    output = bytearray()
    for index in range(8):
        seven_bits = (value >> (49 - 7 * index)) & 0x7F
        byte = seven_bits << 1
        output.append(byte | ((byte.bit_count() + 1) & 1))
    return bytes(output)


@operation("LM Hash", category="Crypto")
def lm_hash(value: Data, _args: Args) -> Data:
    password = to_text(value).upper().encode("latin-1", "replace")[:14].ljust(14, b"\0")
    magic = b"KGS!@#$%"
    digest = _des_block(magic, _lm_des_key(password[:7]))
    digest += _des_block(magic, _lm_des_key(password[7:]))
    return digest.hex().upper()
