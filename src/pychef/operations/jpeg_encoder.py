"""Dependency-free baseline JPEG encoder."""

from __future__ import annotations

import math
import struct
from collections.abc import Sequence

_Pixel = tuple[int, int, int, int]
_ZIGZAG = (
    0,
    1,
    8,
    16,
    9,
    2,
    3,
    10,
    17,
    24,
    32,
    25,
    18,
    11,
    4,
    5,
    12,
    19,
    26,
    33,
    40,
    48,
    41,
    34,
    27,
    20,
    13,
    6,
    7,
    14,
    21,
    28,
    35,
    42,
    49,
    56,
    57,
    50,
    43,
    36,
    29,
    22,
    15,
    23,
    30,
    37,
    44,
    51,
    58,
    59,
    52,
    45,
    38,
    31,
    39,
    46,
    53,
    60,
    61,
    54,
    47,
    55,
    62,
    63,
)
_LUMA_QUANT = (
    16,
    11,
    10,
    16,
    24,
    40,
    51,
    61,
    12,
    12,
    14,
    19,
    26,
    58,
    60,
    55,
    14,
    13,
    16,
    24,
    40,
    57,
    69,
    56,
    14,
    17,
    22,
    29,
    51,
    87,
    80,
    62,
    18,
    22,
    37,
    56,
    68,
    109,
    103,
    77,
    24,
    35,
    55,
    64,
    81,
    104,
    113,
    92,
    49,
    64,
    78,
    87,
    103,
    121,
    120,
    101,
    72,
    92,
    95,
    98,
    112,
    100,
    103,
    99,
)
_CHROMA_QUANT = (
    17,
    18,
    24,
    47,
    99,
    99,
    99,
    99,
    18,
    21,
    26,
    66,
    99,
    99,
    99,
    99,
    24,
    26,
    56,
    99,
    99,
    99,
    99,
    99,
    47,
    66,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
    99,
)
_COSINE = tuple(
    tuple(
        (1 / math.sqrt(2) if frequency == 0 else 1)
        * 0.5
        * math.cos((2 * sample + 1) * frequency * math.pi / 16)
        for sample in range(8)
    )
    for frequency in range(8)
)


def _segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def _quantization(table: tuple[int, ...], quality: int) -> tuple[int, ...]:
    scale = 5000 // quality if quality < 50 else 200 - quality * 2
    return tuple(max(1, min(255, (value * scale + 50) // 100)) for value in table)


def _huffman_spec(
    symbols: tuple[int, ...], length: int
) -> tuple[bytes, dict[int, tuple[int, int]]]:
    counts = bytearray(16)
    counts[length - 1] = len(symbols)
    code = 0
    symbol_index = 0
    mapping: dict[int, tuple[int, int]] = {}
    for current_length, count in enumerate(counts, 1):
        for symbol in symbols[symbol_index : symbol_index + count]:
            mapping[symbol] = (code, current_length)
            code += 1
        symbol_index += count
        code <<= 1
    return bytes(counts) + bytes(symbols), mapping


_DC_SPEC, _DC_CODES = _huffman_spec(tuple(range(12)), 4)
_AC_SYMBOLS = (0x00, 0xF0, *((run << 4) | size for run in range(16) for size in range(1, 11)))
_AC_SPEC, _AC_CODES = _huffman_spec(_AC_SYMBOLS, 8)


class _Bits:
    def __init__(self) -> None:
        self.output = bytearray()
        self.buffer = 0
        self.count = 0

    def write(self, value: int, count: int) -> None:
        self.buffer = (self.buffer << count) | (value & ((1 << count) - 1))
        self.count += count
        while self.count >= 8:
            self.count -= 8
            byte = (self.buffer >> self.count) & 0xFF
            self.output.append(byte)
            if byte == 0xFF:
                self.output.append(0)
        self.buffer &= (1 << self.count) - 1

    def finish(self) -> bytes:
        if self.count:
            self.write((1 << (8 - self.count)) - 1, 8 - self.count)
        return bytes(self.output)


def _magnitude(value: int) -> tuple[int, int]:
    if not value:
        return 0, 0
    size = abs(value).bit_length()
    encoded = value if value > 0 else value + (1 << size) - 1
    return size, encoded


def _dct(block: list[float], quantization: tuple[int, ...]) -> list[int]:
    horizontal = [
        sum(block[row * 8 + sample] * _COSINE[frequency][sample] for sample in range(8))
        for row in range(8)
        for frequency in range(8)
    ]
    return [
        round(
            sum(
                horizontal[row * 8 + horizontal_frequency] * _COSINE[vertical][row]
                for row in range(8)
            )
            / quantization[vertical * 8 + horizontal_frequency]
        )
        for vertical in range(8)
        for horizontal_frequency in range(8)
    ]


def _write_block(bits: _Bits, coefficients: list[int], previous_dc: int) -> int:
    ordered = [coefficients[index] for index in _ZIGZAG]
    difference = ordered[0] - previous_dc
    size, magnitude = _magnitude(difference)
    code, length = _DC_CODES[size]
    bits.write(code, length)
    bits.write(magnitude, size)
    run = 0
    for value in ordered[1:]:
        if not value:
            run += 1
            continue
        while run >= 16:
            code, length = _AC_CODES[0xF0]
            bits.write(code, length)
            run -= 16
        size, magnitude = _magnitude(value)
        code, length = _AC_CODES[(run << 4) | size]
        bits.write(code, length)
        bits.write(magnitude, size)
        run = 0
    if run:
        code, length = _AC_CODES[0]
        bits.write(code, length)
    return ordered[0]


def encode_jpeg(width: int, height: int, pixels: Sequence[_Pixel], quality: int = 80) -> bytes:
    """Encode RGBA pixels as an interoperable 8-bit baseline JFIF image."""
    if not 1 <= quality <= 100:
        raise ValueError("JPEG quality must be between 1 and 100")
    if width < 1 or height < 1 or width * height != len(pixels) or width > 65535 or height > 65535:
        raise ValueError("Invalid JPEG dimensions")
    luma_quant = _quantization(_LUMA_QUANT, quality)
    chroma_quant = _quantization(_CHROMA_QUANT, quality)
    app0 = b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"
    dqt = bytes([0]) + bytes(luma_quant[index] for index in _ZIGZAG)
    dqt += bytes([1]) + bytes(chroma_quant[index] for index in _ZIGZAG)
    sof = b"\x08" + struct.pack(">HHB", height, width, 3)
    sof += b"\x01\x11\0\x02\x11\x01\x03\x11\x01"
    dht = b"\x00" + _DC_SPEC + b"\x10" + _AC_SPEC
    dht += b"\x01" + _DC_SPEC + b"\x11" + _AC_SPEC
    sos = b"\x03\x01\0\x02\x11\x03\x11\0\x3f\0"
    writer = _Bits()
    previous = [0, 0, 0]
    for top in range(0, height, 8):
        for left in range(0, width, 8):
            channels = [[], [], []]
            for y_offset in range(8):
                y = min(height - 1, top + y_offset)
                for x_offset in range(8):
                    x = min(width - 1, left + x_offset)
                    red, green, blue, _alpha = pixels[y * width + x]
                    channels[0].append(0.299 * red + 0.587 * green + 0.114 * blue - 128)
                    channels[1].append(-0.168736 * red - 0.331264 * green + 0.5 * blue)
                    channels[2].append(0.5 * red - 0.418688 * green - 0.081312 * blue)
            for component, samples in enumerate(channels):
                quantization = luma_quant if component == 0 else chroma_quant
                previous[component] = _write_block(
                    writer, _dct(samples, quantization), previous[component]
                )
    return (
        b"\xff\xd8"
        + _segment(0xE0, app0)
        + _segment(0xDB, dqt)
        + _segment(0xC0, sof)
        + _segment(0xC4, dht)
        + _segment(0xDA, sos)
        + writer.finish()
        + b"\xff\xd9"
    )


__all__ = ["encode_jpeg"]
