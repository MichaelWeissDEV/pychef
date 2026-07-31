"""Pure-Python Rabbit stream cipher compatible with CyberChef and RFC 4503."""

from __future__ import annotations

from ..registry import operation
from ..types import Args, Data
from ._utils import arg
from .modern_ciphers import _formatted_input, _formatted_output, _toggle_bytes

_MASK32 = 0xFFFFFFFF
_COUNTER_CONSTANTS = (
    0x4D34D34D,
    0xD34D34D3,
    0x34D34D34,
    0x4D34D34D,
    0xD34D34D3,
    0x34D34D34,
    0x4D34D34D,
    0xD34D34D3,
)


def _rotate_left(value: int, width: int) -> int:
    return ((value << width) | (value >> (32 - width))) & _MASK32


class _RabbitState:
    def __init__(self, key: bytes, iv: bytes, *, little_endian: bool) -> None:
        if little_endian:
            words = [(key[2 * index + 1] << 8) | key[2 * index] for index in range(8)]
        else:
            words = [(key[14 - 2 * index] << 8) | key[15 - 2 * index] for index in range(8)]
        self.state = [0] * 8
        self.counters = [0] * 8
        self.carry = 0
        self.little_endian = little_endian
        for index in range(8):
            if index % 2 == 0:
                self.state[index] = (words[(index + 1) % 8] << 16) | words[index]
                self.counters[index] = (words[(index + 4) % 8] << 16) | words[(index + 5) % 8]
            else:
                self.state[index] = (words[(index + 5) % 8] << 16) | words[(index + 4) % 8]
                self.counters[index] = (words[index] << 16) | words[(index + 1) % 8]
        for _ in range(4):
            self._next_state()
        self.counters = [
            counter ^ self.state[(index + 4) % 8]
            for index, counter in enumerate(self.counters)
        ]
        if iv:
            self._apply_iv(iv)

    def _update_counters(self) -> None:
        for index, constant in enumerate(_COUNTER_CONSTANTS):
            total = self.counters[index] + constant + self.carry
            self.carry = total >> 32
            self.counters[index] = total & _MASK32

    def _next_state(self) -> None:
        self._update_counters()
        nonlinear = []
        for state, counter in zip(self.state, self.counters, strict=True):
            value = (state + counter) & _MASK32
            square = value * value
            nonlinear.append((square ^ (square >> 32)) & _MASK32)
        self.state = [
            (nonlinear[0] + _rotate_left(nonlinear[7], 16) + _rotate_left(nonlinear[6], 16)) & _MASK32,
            (nonlinear[1] + _rotate_left(nonlinear[0], 8) + nonlinear[7]) & _MASK32,
            (nonlinear[2] + _rotate_left(nonlinear[1], 16) + _rotate_left(nonlinear[0], 16)) & _MASK32,
            (nonlinear[3] + _rotate_left(nonlinear[2], 8) + nonlinear[1]) & _MASK32,
            (nonlinear[4] + _rotate_left(nonlinear[3], 16) + _rotate_left(nonlinear[2], 16)) & _MASK32,
            (nonlinear[5] + _rotate_left(nonlinear[4], 8) + nonlinear[3]) & _MASK32,
            (nonlinear[6] + _rotate_left(nonlinear[5], 16) + _rotate_left(nonlinear[4], 16)) & _MASK32,
            (nonlinear[7] + _rotate_left(nonlinear[6], 8) + nonlinear[5]) & _MASK32,
        ]

    def _iv_word(self, iv: bytes, a: int, b: int, c: int, d: int) -> int:
        if self.little_endian:
            indexes = (a, b, c, d)
        else:
            indexes = (7 - a, 7 - b, 7 - c, 7 - d)
        return sum(iv[index] << shift for index, shift in zip(indexes, (24, 16, 8, 0), strict=True))

    def _apply_iv(self, iv: bytes) -> None:
        values = (
            self._iv_word(iv, 3, 2, 1, 0),
            self._iv_word(iv, 7, 6, 3, 2),
            self._iv_word(iv, 7, 6, 5, 4),
            self._iv_word(iv, 5, 4, 1, 0),
        )
        for index in range(8):
            self.counters[index] ^= values[index % 4]
        for _ in range(4):
            self._next_state()

    def extract(self) -> bytes:
        self._next_state()
        words = (
            (self.state[6] >> 16) ^ (self.state[1] & 0xFFFF),
            (self.state[6] & 0xFFFF) ^ (self.state[3] >> 16),
            (self.state[4] >> 16) ^ (self.state[7] & 0xFFFF),
            (self.state[4] & 0xFFFF) ^ (self.state[1] >> 16),
            (self.state[2] >> 16) ^ (self.state[5] & 0xFFFF),
            (self.state[2] & 0xFFFF) ^ (self.state[7] >> 16),
            (self.state[0] >> 16) ^ (self.state[3] & 0xFFFF),
            (self.state[0] & 0xFFFF) ^ (self.state[5] >> 16),
        )
        stream = b"".join((word & 0xFFFF).to_bytes(2, "big") for word in words)
        return stream[::-1] if self.little_endian else stream


def _crypt(data: bytes, key: bytes, iv: bytes, *, little_endian: bool) -> bytes:
    state = _RabbitState(key, iv, little_endian=little_endian)
    output = bytearray()
    complete_length = len(data) - len(data) % 16
    for position in range(0, complete_length, 16):
        stream = state.extract()
        output.extend(
            byte ^ key_byte
            for byte, key_byte in zip(data[position : position + 16], stream, strict=True)
        )
    remaining = data[complete_length:]
    if remaining:
        stream = state.extract()
        if not little_endian:
            stream = stream[-len(remaining) :]
        output.extend(byte ^ key_byte for byte, key_byte in zip(remaining, stream))
    return bytes(output)


@operation("Rabbit", category="Ciphers")
def rabbit(value: Data, args: Args) -> Data:
    key = _toggle_bytes(arg(args, 0, {"option": "Hex", "string": ""}))
    iv = _toggle_bytes(arg(args, 1, {"option": "Hex", "string": ""}))
    if len(key) != 16:
        raise ValueError(f"Invalid key length: {len(key)} bytes (expected: 16)")
    if len(iv) not in {0, 8}:
        raise ValueError(f"Invalid IV length: {len(iv)} bytes (expected: 0 or 8)")
    little_endian = str(arg(args, 2, "Big")) == "Little"
    input_format = str(arg(args, 3, "Raw"))
    output_format = str(arg(args, 4, "Raw"))
    data = _formatted_input(value, input_format)
    return _formatted_output(_crypt(data, key, iv, little_endian=little_endian), output_format)
