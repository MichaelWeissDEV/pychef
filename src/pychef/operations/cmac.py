"""AES- and Triple-DES-based CMAC as specified by NIST SP 800-38B."""

from __future__ import annotations

from collections.abc import Callable

from ..registry import operation
from ..types import Args, Data, to_bytes
from ._utils import arg
from .aes import _encrypt_block as _aes_encrypt_block
from .des import _triple_des_block
from .modern_ciphers import _toggle_bytes

_BlockEncryptor = Callable[[bytes], bytes]


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _double(block: bytes, reduction: int) -> bytes:
    top_bit = block[0] & 0x80
    value = (int.from_bytes(block, "big") << 1) & ((1 << (8 * len(block))) - 1)
    if top_bit:
        value ^= reduction
    return value.to_bytes(len(block), "big")


def _cmac(data: bytes, block_size: int, reduction: int, encrypt: _BlockEncryptor) -> bytes:
    first_subkey = _double(encrypt(bytes(block_size)), reduction)
    second_subkey = _double(first_subkey, reduction)
    complete = bool(data) and len(data) % block_size == 0
    block_count = max(1, (len(data) + block_size - 1) // block_size)
    last_offset = (block_count - 1) * block_size
    last = data[last_offset:]
    if complete:
        last = _xor(last, first_subkey)
    else:
        last = _xor(last + b"\x80" + bytes(block_size - len(last) - 1), second_subkey)
    state = bytes(block_size)
    for position in range(0, last_offset, block_size):
        state = encrypt(_xor(state, data[position : position + block_size]))
    return encrypt(_xor(state, last))


@operation("CMAC", category="Crypto")
def cmac(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    algorithm = str(arg(args, 1, "AES"))
    if algorithm == "AES":
        if len(key) not in {16, 24, 32}:
            raise ValueError(
                f"The key for AES must be either 16, 24, or 32 bytes (currently {len(key)} bytes)"
            )

        def encrypt(block: bytes) -> bytes:
            return _aes_encrypt_block(block, key)

        block_size, reduction = 16, 0x87
    elif algorithm == "Triple DES":
        if len(key) not in {16, 24}:
            raise ValueError(
                f"The key for Triple DES must be 16 or 24 bytes (currently {len(key)} bytes)"
            )
        if len(key) == 16:
            key += key[:8]

        def encrypt(block: bytes) -> bytes:
            return _triple_des_block(block, key)

        block_size, reduction = 8, 0x1B
    else:
        raise ValueError("Undefined encryption algorithm")
    return _cmac(to_bytes(value), block_size, reduction, encrypt).hex()
