"""Pure-Python SM4 with the block modes exposed by CyberChef."""

from __future__ import annotations

from functools import lru_cache

from ..registry import implementation
from ..types import Args, Data
from ._utils import arg
from .modern_ciphers import _formatted_input, _toggle_bytes

_MASK = 0xFFFFFFFF
_S_BOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948"
)
_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
_CK = tuple(
    int.from_bytes(bytes(((4 * index + offset) * 7) & 0xFF for offset in range(4)), "big")
    for index in range(32)
)


def _rotate_left(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & _MASK


def _substitute(value: int) -> int:
    return (
        (_S_BOX[(value >> 24) & 0xFF] << 24)
        | (_S_BOX[(value >> 16) & 0xFF] << 16)
        | (_S_BOX[(value >> 8) & 0xFF] << 8)
        | _S_BOX[value & 0xFF]
    )


def _linear(value: int) -> int:
    value = _substitute(value)
    return (
        value
        ^ _rotate_left(value, 2)
        ^ _rotate_left(value, 10)
        ^ _rotate_left(value, 18)
        ^ _rotate_left(value, 24)
    )


def _key_linear(value: int) -> int:
    value = _substitute(value)
    return value ^ _rotate_left(value, 13) ^ _rotate_left(value, 23)


@lru_cache(maxsize=256)
def _round_keys(key: bytes) -> tuple[int, ...]:
    words = [int.from_bytes(key[position : position + 4], "big") for position in range(0, 16, 4)]
    words = [word ^ constant for word, constant in zip(words, _FK, strict=True)]
    output = []
    for index, constant in enumerate(_CK):
        value = words[index] ^ _key_linear(
            words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ constant
        )
        words.append(value & _MASK)
        output.append(value & _MASK)
    return tuple(output)


def _crypt_block(block: bytes, key: bytes, *, decrypting: bool = False) -> bytes:
    if len(block) != 16:
        raise ValueError("SM4 blocks must be 16 bytes")
    words = [int.from_bytes(block[position : position + 4], "big") for position in range(0, 16, 4)]
    keys = reversed(_round_keys(key)) if decrypting else _round_keys(key)
    for round_key in keys:
        words.append((words[-4] ^ _linear(words[-3] ^ words[-2] ^ words[-1] ^ round_key)) & _MASK)
    return b"".join(word.to_bytes(4, "big") for word in reversed(words[-4:]))


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _crypt(
    data: bytes,
    key: bytes,
    iv: bytes,
    mode: str,
    *,
    decrypting: bool,
    no_padding: bool,
) -> bytes:
    if not data:
        return b""
    if mode in {"ECB", "CBC"}:
        if decrypting:
            if len(data) % 16:
                raise ValueError(
                    "With ECB or CBC modes, the input must be divisible into 16 byte blocks."
                )
        elif no_padding:
            if len(data) % 16:
                raise ValueError(
                    f"No padding requested in {mode} mode but input is not a 16-byte multiple."
                )
        else:
            padding = 16 - len(data) % 16
            data += bytes([padding]) * padding
    output = bytearray()
    feedback = iv
    counter = int.from_bytes(iv[-4:], "big") if iv else 0
    for position in range(0, len(data), 16):
        block = data[position : position + 16]
        if mode == "ECB":
            output.extend(_crypt_block(block, key, decrypting=decrypting))
        elif mode == "CBC":
            if decrypting:
                output.extend(_xor(_crypt_block(block, key, decrypting=True), feedback))
                feedback = block
            else:
                feedback = _crypt_block(_xor(block, feedback), key)
                output.extend(feedback)
        elif mode == "CFB":
            transformed = _xor(block, _crypt_block(feedback, key)[: len(block)])
            output.extend(transformed)
            feedback = block.ljust(16, b"\0") if decrypting else transformed.ljust(16, b"\0")
        elif mode == "OFB":
            feedback = _crypt_block(feedback, key)
            output.extend(_xor(block, feedback[: len(block)]))
        elif mode == "CTR":
            current = iv[:-4] + counter.to_bytes(4, "big")
            output.extend(_xor(block, _crypt_block(current, key)[: len(block)]))
            counter = (counter + 1) & _MASK
        else:
            raise ValueError(f"Invalid block cipher mode: {mode}")
    result = bytes(output)
    if decrypting and mode in {"ECB", "CBC"} and not no_padding:
        padding = result[-1]
        if not 1 <= padding <= 16 or result[-padding:] != bytes([padding]) * padding:
            raise ValueError("Invalid PKCS#7 padding.")
        result = result[:-padding]
    return result


def _sm4(value: Data, args: Args, *, decrypting: bool) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    mode_arg = str(arg(args, 2, "CBC"))
    mode = mode_arg.split("/", 1)[0]
    no_padding = mode_arg.endswith("NoPadding")
    if len(key) != 16:
        raise ValueError(
            f"Invalid key length: {len(key)} bytes\n\nSM4 uses a key length of 16 bytes (128 bits)."
        )
    if mode != "ECB" and len(iv) != 16:
        raise ValueError(
            f"Invalid IV length: {len(iv)} bytes\n\n"
            "SM4 uses an IV length of 16 bytes (128 bits).\n"
            "Make sure you have specified the type correctly (e.g. Hex vs UTF8)."
        )
    input_format = str(arg(args, 3, "Raw"))
    output_format = str(arg(args, 4, "Hex"))
    result = _crypt(
        _formatted_input(value, input_format),
        key,
        iv,
        mode,
        decrypting=decrypting,
        no_padding=no_padding,
    )
    if output_format.upper() == "HEX":
        return " ".join(f"{byte:02x}" for byte in result)
    return result


@implementation("SM4 Encrypt", category="Ciphers")
def sm4_encrypt(value: Data, args: Args) -> Data:
    return _sm4(value, args, decrypting=False)


@implementation("SM4 Decrypt", category="Ciphers")
def sm4_decrypt(value: Data, args: Args) -> Data:
    return _sm4(value, args, decrypting=True)
