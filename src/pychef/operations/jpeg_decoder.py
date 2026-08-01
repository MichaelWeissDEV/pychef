"""Dependency-free sequential baseline JPEG decoder."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field

from .jpeg_encoder import _COSINE, _ZIGZAG

_Pixel = tuple[int, int, int, int]


@dataclass(slots=True)
class _Component:
    identifier: int
    horizontal: int
    vertical: int
    quantization: int
    dc_table: int = 0
    ac_table: int = 0
    previous_dc: int = 0
    plane_width: int = 0
    plane: list[int] = field(default_factory=list)


class _Bits:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def read(self, count: int) -> int:
        if self.position + count > len(self.data) * 8:
            raise ValueError("Truncated JPEG entropy stream")
        value = 0
        for _ in range(count):
            byte = self.data[self.position >> 3]
            value = (value << 1) | ((byte >> (7 - (self.position & 7))) & 1)
            self.position += 1
        return value

    def align(self) -> None:
        self.position = (self.position + 7) & ~7


def _huffman_table(counts: bytes, symbols: bytes) -> dict[tuple[int, int], int]:
    output: dict[tuple[int, int], int] = {}
    code = 0
    position = 0
    for length, count in enumerate(counts, 1):
        for symbol in symbols[position : position + count]:
            output[(length, code)] = symbol
            code += 1
        position += count
        code <<= 1
    return output


def _huffman(bits: _Bits, table: dict[tuple[int, int], int]) -> int:
    code = 0
    for length in range(1, 17):
        code = (code << 1) | bits.read(1)
        symbol = table.get((length, code))
        if symbol is not None:
            return symbol
    raise ValueError("Invalid JPEG Huffman code")


def _magnitude(bits: _Bits, size: int) -> int:
    if not size:
        return 0
    value = bits.read(size)
    return value if value >= 1 << (size - 1) else value - (1 << size) + 1


def _block(
    bits: _Bits,
    component: _Component,
    quantization: tuple[int, ...],
    dc_tables: dict[int, dict[tuple[int, int], int]],
    ac_tables: dict[int, dict[tuple[int, int], int]],
) -> list[int]:
    coefficients = [0] * 64
    dc_size = _huffman(bits, dc_tables[component.dc_table])
    component.previous_dc += _magnitude(bits, dc_size)
    coefficients[0] = component.previous_dc * quantization[0]
    position = 1
    while position < 64:
        symbol = _huffman(bits, ac_tables[component.ac_table])
        if symbol == 0:
            break
        if symbol == 0xF0:
            position += 16
            continue
        run, size = symbol >> 4, symbol & 15
        position += run
        if not size or position >= 64:
            raise ValueError("Invalid JPEG AC coefficient run")
        natural = _ZIGZAG[position]
        coefficients[natural] = _magnitude(bits, size) * quantization[natural]
        position += 1
    return coefficients


def _idct(coefficients: list[int]) -> list[int]:
    pixels: list[int] = []
    for y in range(8):
        for x in range(8):
            value = sum(
                coefficients[vertical * 8 + horizontal]
                * _COSINE[horizontal][x]
                * _COSINE[vertical][y]
                for vertical in range(8)
                for horizontal in range(8)
            )
            pixels.append(max(0, min(255, round(value + 128))))
    return pixels


def _entropy(data: bytes, position: int) -> tuple[bytes, tuple[int, ...]]:
    output = bytearray()
    restarts: list[int] = []
    while position < len(data):
        byte = data[position]
        position += 1
        if byte != 0xFF:
            output.append(byte)
            continue
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            raise ValueError("Truncated JPEG marker")
        marker = data[position]
        position += 1
        if marker == 0:
            output.append(0xFF)
        elif 0xD0 <= marker <= 0xD7:
            restarts.append(len(output))
        elif marker == 0xD9:
            return bytes(output), tuple(restarts)
        else:
            raise ValueError(f"Unsupported marker after JPEG scan: 0x{marker:02x}")
    raise ValueError("JPEG end-of-image marker is missing")


def _colour(red: float, green: float, blue: float) -> tuple[int, int, int, int]:
    return (
        max(0, min(255, round(red))),
        max(0, min(255, round(green))),
        max(0, min(255, round(blue))),
        255,
    )


def decode_jpeg(data: bytes) -> tuple[int, int, list[_Pixel]]:
    """Decode a complete sequential baseline JPEG image into RGBA pixels."""
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("Input is not a JPEG image")
    position = 2
    width = height = 0
    components: dict[int, _Component] = {}
    quantization: dict[int, tuple[int, ...]] = {}
    dc_tables: dict[int, dict[tuple[int, int], int]] = {}
    ac_tables: dict[int, dict[tuple[int, int], int]] = {}
    restart_interval = 0
    scan_components: list[_Component] = []
    scan_position = -1
    while position < len(data):
        if data[position] != 0xFF:
            raise ValueError("Invalid JPEG marker framing")
        while position < len(data) and data[position] == 0xFF:
            position += 1
        marker = data[position]
        position += 1
        if marker == 0xD9:
            break
        if marker in {0xD8, 0x01} or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > len(data):
            raise ValueError("Truncated JPEG segment")
        length = struct.unpack(">H", data[position : position + 2])[0]
        payload = data[position + 2 : position + length]
        if length < 2 or len(payload) != length - 2:
            raise ValueError("Truncated JPEG segment")
        position += length
        if marker == 0xDB:
            cursor = 0
            while cursor < len(payload):
                specification = payload[cursor]
                cursor += 1
                precision, identifier = specification >> 4, specification & 15
                item_size = 2 if precision else 1
                raw = payload[cursor : cursor + 64 * item_size]
                if len(raw) != 64 * item_size:
                    raise ValueError("Truncated JPEG quantization table")
                values = struct.unpack(f">64{'H' if precision else 'B'}", raw)
                natural = [0] * 64
                for zigzag_index, value in enumerate(values):
                    natural[_ZIGZAG[zigzag_index]] = value
                quantization[identifier] = tuple(natural)
                cursor += len(raw)
        elif marker == 0xC4:
            cursor = 0
            while cursor < len(payload):
                specification = payload[cursor]
                counts = payload[cursor + 1 : cursor + 17]
                symbol_count = sum(counts)
                symbols = payload[cursor + 17 : cursor + 17 + symbol_count]
                if len(counts) != 16 or len(symbols) != symbol_count:
                    raise ValueError("Truncated JPEG Huffman table")
                target = ac_tables if specification >> 4 else dc_tables
                target[specification & 15] = _huffman_table(counts, symbols)
                cursor += 17 + symbol_count
        elif marker == 0xC0:
            if len(payload) < 6 or payload[0] != 8:
                raise ValueError("Only 8-bit baseline JPEG is supported")
            height, width, count = struct.unpack(">HHB", payload[1:6])
            if len(payload) != 6 + count * 3:
                raise ValueError("Invalid JPEG frame header")
            if width < 1 or height < 1 or width * height > 100_000_000:
                raise ValueError("Invalid or unsafe JPEG dimensions")
            for index in range(count):
                identifier, sampling, table = payload[6 + index * 3 : 9 + index * 3]
                horizontal, vertical = sampling >> 4, sampling & 15
                if horizontal < 1 or vertical < 1:
                    raise ValueError("Invalid JPEG component sampling")
                components[identifier] = _Component(identifier, horizontal, vertical, table)
        elif marker == 0xDD:
            if len(payload) != 2:
                raise ValueError("Invalid JPEG restart interval")
            restart_interval = struct.unpack(">H", payload)[0]
        elif marker == 0xDA:
            count = payload[0]
            if len(payload) != 1 + count * 2 + 3 or payload[-3:] != b"\0?\0":
                raise ValueError("Only sequential baseline JPEG scans are supported")
            for index in range(count):
                identifier, tables = payload[1 + index * 2 : 3 + index * 2]
                component = components.get(identifier)
                if component is None:
                    raise ValueError("JPEG scan references an unknown component")
                component.dc_table, component.ac_table = tables >> 4, tables & 15
                scan_components.append(component)
            scan_position = position
            break
        elif marker in {0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
            raise ValueError("Only sequential baseline JPEG frames are supported")
    if scan_position < 0 or not components or not scan_components:
        raise ValueError("JPEG frame or scan header is missing")
    entropy, restart_offsets = _entropy(data, scan_position)
    bits = _Bits(entropy)
    maximum_horizontal = max(item.horizontal for item in components.values())
    maximum_vertical = max(item.vertical for item in components.values())
    columns = math.ceil(width / (maximum_horizontal * 8))
    rows = math.ceil(height / (maximum_vertical * 8))
    for component in components.values():
        component.plane_width = columns * component.horizontal * 8
        plane_height = rows * component.vertical * 8
        component.plane = [0] * (component.plane_width * plane_height)
    restart_index = 0
    mcu_index = 0
    for mcu_y in range(rows):
        for mcu_x in range(columns):
            if restart_interval and mcu_index and mcu_index % restart_interval == 0:
                bits.align()
                invalid_restart = restart_index >= len(restart_offsets) or (
                    bits.position // 8 != restart_offsets[restart_index]
                )
                if invalid_restart:
                    raise ValueError("JPEG restart marker is missing or misplaced")
                restart_index += 1
                for component in components.values():
                    component.previous_dc = 0
            for component in scan_components:
                table = quantization.get(component.quantization)
                if table is None:
                    raise ValueError("JPEG quantization table is missing")
                for vertical in range(component.vertical):
                    for horizontal in range(component.horizontal):
                        decoded = _idct(_block(bits, component, table, dc_tables, ac_tables))
                        block_x = (mcu_x * component.horizontal + horizontal) * 8
                        block_y = (mcu_y * component.vertical + vertical) * 8
                        for row in range(8):
                            start = (block_y + row) * component.plane_width + block_x
                            component.plane[start : start + 8] = decoded[row * 8 : row * 8 + 8]
            mcu_index += 1
    ordered = list(components.values())
    pixels: list[_Pixel] = []
    for y in range(height):
        for x in range(width):
            samples = [
                component.plane[
                    (y * component.vertical // maximum_vertical) * component.plane_width
                    + x * component.horizontal // maximum_horizontal
                ]
                for component in ordered
            ]
            if len(samples) == 1:
                pixels.append((samples[0], samples[0], samples[0], 255))
            elif len(samples) == 3:
                luminance, blue_difference, red_difference = samples
                pixels.append(
                    _colour(
                        luminance + 1.402 * (red_difference - 128),
                        luminance
                        - 0.344136 * (blue_difference - 128)
                        - 0.714136 * (red_difference - 128),
                        luminance + 1.772 * (blue_difference - 128),
                    )
                )
            else:
                raise ValueError("Only greyscale and YCbCr JPEG images are supported")
    return width, height, pixels


__all__ = ["decode_jpeg"]
