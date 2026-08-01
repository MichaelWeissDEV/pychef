"""Dependency-free raster image parsing, generation, and transformation."""

from __future__ import annotations

import base64
import colorsys
import hashlib
import math
import random
import re
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg, char_rep, require_int
from .jpeg_decoder import decode_jpeg as _jpeg_decode
from .jpeg_encoder import encode_jpeg as _jpeg_encode

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_Pixel = tuple[int, int, int, int]


@dataclass(slots=True)
class _Image:
    width: int
    height: int
    pixels: list[_Pixel]

    def __post_init__(self) -> None:
        if self.width < 1 or self.height < 1 or self.width * self.height != len(self.pixels):
            raise ValueError("Invalid image dimensions or pixel count")
        if self.width * self.height > 100_000_000:
            raise ValueError("Image is too large to process safely")

    def get(self, x: int, y: int) -> _Pixel:
        return self.pixels[y * self.width + x]


def _chunk(name: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + name
        + payload
        + struct.pack(">I", zlib.crc32(name + payload))
    )


def _paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    distances = (abs(estimate - left), abs(estimate - above), abs(estimate - upper_left))
    return (left, above, upper_left)[distances.index(min(distances))]


def _png_decode(data: bytes) -> tuple[_Image, dict[str, bytes]]:
    if not data.startswith(_PNG_SIGNATURE):
        raise ValueError("Input is not a PNG image")
    position = 8
    width = height = colour_type = bit_depth = interlace = 0
    compressed = bytearray()
    metadata: dict[str, bytes] = {}
    while position + 12 <= len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        name = data[position + 4 : position + 8]
        payload = data[position + 8 : position + 8 + length]
        checksum = data[position + 8 + length : position + 12 + length]
        if len(payload) != length or len(checksum) != 4:
            raise ValueError("Truncated PNG chunk")
        if zlib.crc32(name + payload).to_bytes(4, "big") != checksum:
            raise ValueError(f"Invalid PNG {name.decode('latin-1')} checksum")
        position += 12 + length
        if name == b"IHDR":
            width, height, bit_depth, colour_type, _, _, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
        elif name == b"IDAT":
            compressed.extend(payload)
        elif name == b"tEXt" and b"\0" in payload:
            key, value = payload.split(b"\0", 1)
            metadata[key.decode("latin-1")] = value
        elif name == b"IEND":
            break
    if bit_depth != 8 or colour_type not in {0, 2, 4, 6} or interlace:
        raise ValueError("Only non-interlaced 8-bit greyscale/RGB/RGBA PNG images are supported")
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[colour_type]
    if width < 1 or height < 1 or width * height > 100_000_000:
        raise ValueError("Invalid or unsafe PNG dimensions")
    maximum = height * (1 + width * channels)
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(bytes(compressed), maximum + 1)
    if len(raw) > maximum or not decompressor.eof:
        raise ValueError("PNG compressed data exceeds its declared dimensions")
    stride = width * channels
    if len(raw) != height * (stride + 1):
        raise ValueError("PNG scanline length does not match its dimensions")
    rows: list[bytes] = []
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        source = raw[cursor + 1 : cursor + 1 + stride]
        cursor += stride + 1
        previous = rows[-1] if rows else b"\0" * stride
        row = bytearray(stride)
        for index, byte in enumerate(source):
            left = row[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            predictor = {
                0: 0,
                1: left,
                2: above,
                3: (left + above) // 2,
                4: _paeth(left, above, upper_left),
            }.get(filter_type)
            if predictor is None:
                raise ValueError(f"Invalid PNG filter type: {filter_type}")
            row[index] = (byte + predictor) & 255
        rows.append(bytes(row))
    pixels: list[_Pixel] = []
    for row in rows:
        for index in range(0, len(row), channels):
            sample = row[index : index + channels]
            if colour_type == 0:
                pixels.append((sample[0], sample[0], sample[0], 255))
            elif colour_type == 2:
                pixels.append((sample[0], sample[1], sample[2], 255))
            elif colour_type == 4:
                pixels.append((sample[0], sample[0], sample[0], sample[1]))
            else:
                pixels.append((sample[0], sample[1], sample[2], sample[3]))
    return _Image(width, height, pixels), metadata


def _png_encode(image: _Image, metadata: dict[str, bytes] | None = None, level: int = 9) -> bytes:
    scanlines = bytearray()
    for y in range(image.height):
        scanlines.append(0)
        for x in range(image.width):
            scanlines.extend(image.get(x, y))
    header = struct.pack(">IIBBBBB", image.width, image.height, 8, 6, 0, 0, 0)
    chunks = [_chunk(b"IHDR", header)]
    for key, value in (metadata or {}).items():
        safe_key = key.encode("latin-1", "replace")[:79].replace(b"\0", b"")
        chunks.append(_chunk(b"tEXt", safe_key + b"\0" + value))
    chunks.extend(
        (
            _chunk(b"IDAT", zlib.compress(bytes(scanlines), max(0, min(level, 9)))),
            _chunk(b"IEND", b""),
        )
    )
    return _PNG_SIGNATURE + b"".join(chunks)


def _bmp_decode(data: bytes) -> _Image:
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("Input is not a supported BMP image")
    offset = int.from_bytes(data[10:14], "little")
    width = int.from_bytes(data[18:22], "little", signed=True)
    signed_height = int.from_bytes(data[22:26], "little", signed=True)
    bits = int.from_bytes(data[28:30], "little")
    compression = int.from_bytes(data[30:34], "little")
    if width <= 0 or not signed_height or bits not in {24, 32} or compression != 0:
        raise ValueError("Only uncompressed 24/32-bit BMP images are supported")
    height = abs(signed_height)
    stride = ((width * bits + 31) // 32) * 4
    if offset + stride * height > len(data):
        raise ValueError("Truncated BMP pixel data")
    pixels: list[_Pixel] = []
    rows = range(height) if signed_height < 0 else range(height - 1, -1, -1)
    for y in rows:
        row = data[offset + y * stride : offset + (y + 1) * stride]
        for x in range(width):
            sample = row[x * (bits // 8) : (x + 1) * (bits // 8)]
            pixels.append((sample[2], sample[1], sample[0], sample[3] if bits == 32 else 255))
    return _Image(width, height, pixels)


def _bmp_encode(image: _Image) -> bytes:
    pixel_data = bytearray()
    for y in range(image.height - 1, -1, -1):
        for x in range(image.width):
            red, green, blue, alpha = image.get(x, y)
            pixel_data.extend((blue, green, red, alpha))
    header = (
        b"BM"
        + (54 + len(pixel_data)).to_bytes(4, "little")
        + b"\0\0\0\0"
        + (54).to_bytes(4, "little")
    )
    dib = (40).to_bytes(4, "little") + image.width.to_bytes(4, "little", signed=True)
    dib += image.height.to_bytes(4, "little", signed=True) + b"\x01\0\x20\0" + b"\0" * 24
    return header + dib + pixel_data


def _ppm_decode(data: bytes) -> _Image:
    match = re.match(rb"P6\s+(?:#[^\n]*\s+)*(\d+)\s+(\d+)\s+(\d+)\s", data)
    if not match or int(match.group(3)) != 255:
        raise ValueError("Input is not an 8-bit binary PPM image")
    width, height = int(match.group(1)), int(match.group(2))
    raw = data[match.end() :]
    if len(raw) != width * height * 3:
        raise ValueError("PPM pixel count does not match its dimensions")
    return _Image(
        width, height, [(raw[i], raw[i + 1], raw[i + 2], 255) for i in range(0, len(raw), 3)]
    )


def _ppm_encode(image: _Image) -> bytes:
    raw = bytes(channel for pixel in image.pixels for channel in pixel[:3])
    return f"P6\n{image.width} {image.height}\n255\n".encode() + raw


def _tiff_values(data: bytes, endian: str, entry: bytes) -> tuple[int, ...]:
    kind, count = struct.unpack(f"{endian}HI", entry[2:8])
    widths = {1: 1, 3: 2, 4: 4}
    if kind not in widths:
        raise ValueError(f"Unsupported TIFF field type: {kind}")
    width = widths[kind]
    total = width * count
    raw = entry[8:12] if total <= 4 else data[struct.unpack(f"{endian}I", entry[8:12])[0] :]
    if len(raw) < total:
        raise ValueError("Truncated TIFF field")
    formats = {1: "B", 3: "H", 4: "I"}
    return struct.unpack(f"{endian}{count}{formats[kind]}", raw[:total])


def _tiff_decode(data: bytes) -> _Image:
    if len(data) < 8 or data[:2] not in {b"II", b"MM"}:
        raise ValueError("Input is not a TIFF image")
    endian = "<" if data[:2] == b"II" else ">"
    if struct.unpack(f"{endian}H", data[2:4])[0] != 42:
        raise ValueError("Invalid TIFF signature")
    directory_offset = struct.unpack(f"{endian}I", data[4:8])[0]
    if directory_offset + 2 > len(data):
        raise ValueError("Truncated TIFF directory")
    count = struct.unpack(f"{endian}H", data[directory_offset : directory_offset + 2])[0]
    fields: dict[int, tuple[int, ...]] = {}
    for index in range(count):
        start = directory_offset + 2 + index * 12
        entry = data[start : start + 12]
        if len(entry) != 12:
            raise ValueError("Truncated TIFF directory entry")
        fields[struct.unpack(f"{endian}H", entry[:2])[0]] = _tiff_values(data, endian, entry)

    def scalar(tag: int, default: int = 0) -> int:
        values = fields.get(tag)
        return values[0] if values else default

    width, height = scalar(256), scalar(257)
    compression = scalar(259, 1)
    photometric = scalar(262, 2)
    samples = scalar(277, 1)
    planar = scalar(284, 1)
    bits = fields.get(258, (8,) * samples)
    offsets, byte_counts = fields.get(273, ()), fields.get(279, ())
    if width < 1 or height < 1 or width * height > 100_000_000:
        raise ValueError("Invalid or unsafe TIFF dimensions")
    if compression != 1 or planar != 1 or samples not in {1, 2, 3, 4}:
        raise ValueError("Only uncompressed chunky 8-bit TIFF images are supported")
    if any(size != 8 for size in bits) or len(offsets) != len(byte_counts) or not offsets:
        raise ValueError("Unsupported or incomplete TIFF strip layout")
    raw = bytearray()
    for offset, byte_count in zip(offsets, byte_counts, strict=True):
        strip = data[offset : offset + byte_count]
        if len(strip) != byte_count:
            raise ValueError("Truncated TIFF strip")
        raw.extend(strip)
    expected = width * height * samples
    if len(raw) < expected:
        raise ValueError("TIFF pixel data is shorter than its dimensions")
    pixels: list[_Pixel] = []
    for index in range(0, expected, samples):
        sample = raw[index : index + samples]
        if photometric in {0, 1} and samples in {1, 2}:
            grey = sample[0] if photometric == 1 else 255 - sample[0]
            pixels.append((grey, grey, grey, sample[1] if samples == 2 else 255))
        elif photometric == 2 and samples in {3, 4}:
            pixels.append((sample[0], sample[1], sample[2], sample[3] if samples == 4 else 255))
        else:
            raise ValueError("Unsupported TIFF photometric interpretation")
    return _Image(width, height, pixels)


def _tiff_encode(image: _Image) -> bytes:
    entries = 11
    directory_size = 2 + entries * 12 + 4
    bits_offset = 8 + directory_size
    pixel_offset = bits_offset + 8
    raw = bytes(channel for pixel in image.pixels for channel in pixel)

    def entry(tag: int, kind: int, count: int, value: int | bytes) -> bytes:
        encoded = value if isinstance(value, bytes) else struct.pack("<I", value)
        return struct.pack("<HHI", tag, kind, count) + encoded.ljust(4, b"\0")[:4]

    fields = (
        entry(256, 4, 1, image.width),
        entry(257, 4, 1, image.height),
        entry(258, 3, 4, bits_offset),
        entry(259, 3, 1, struct.pack("<H", 1)),
        entry(262, 3, 1, struct.pack("<H", 2)),
        entry(273, 4, 1, pixel_offset),
        entry(277, 3, 1, struct.pack("<H", 4)),
        entry(278, 4, 1, image.height),
        entry(279, 4, 1, len(raw)),
        entry(284, 3, 1, struct.pack("<H", 1)),
        entry(338, 3, 1, struct.pack("<H", 2)),
    )
    return (
        b"II*\0\x08\0\0\0"
        + struct.pack("<H", entries)
        + b"".join(fields)
        + b"\0" * 4
        + struct.pack("<4H", 8, 8, 8, 8)
        + raw
    )


def _gif_subblocks(data: bytes, position: int) -> tuple[bytes, int]:
    output = bytearray()
    while True:
        if position >= len(data):
            raise ValueError("Truncated GIF sub-block stream")
        length = data[position]
        position += 1
        if not length:
            return bytes(output), position
        block = data[position : position + length]
        if len(block) != length:
            raise ValueError("Truncated GIF sub-block")
        output.extend(block)
        position += length


def _gif_lzw(data: bytes, minimum_size: int, expected: int) -> list[int]:
    if not 2 <= minimum_size <= 8:
        raise ValueError("Invalid GIF LZW code size")
    clear = 1 << minimum_size
    end = clear + 1
    code_size = minimum_size + 1
    table = {index: bytes([index]) for index in range(clear)}
    next_code = end + 1
    bit_position = 0
    previous: bytes | None = None
    output = bytearray()

    def read_code() -> int:
        nonlocal bit_position
        if bit_position + code_size > len(data) * 8:
            raise ValueError("Truncated GIF LZW stream")
        value = 0
        for offset in range(code_size):
            source_position = bit_position + offset
            value |= ((data[source_position >> 3] >> (source_position & 7)) & 1) << offset
        bit_position += code_size
        return value

    while len(output) < expected:
        code = read_code()
        if code == clear:
            table = {index: bytes([index]) for index in range(clear)}
            code_size = minimum_size + 1
            next_code = end + 1
            previous = None
            continue
        if code == end:
            break
        if code in table:
            entry = table[code]
        elif code == next_code and previous is not None:
            entry = previous + previous[:1]
        else:
            raise ValueError("Invalid GIF LZW code")
        output.extend(entry)
        if previous is not None and next_code < 4096:
            table[next_code] = previous + entry[:1]
            next_code += 1
            if next_code == 1 << code_size and code_size < 12:
                code_size += 1
        previous = entry
    if len(output) < expected:
        raise ValueError("GIF pixel stream is shorter than its image descriptor")
    return list(output[:expected])


def _gif_decode(data: bytes) -> _Image:
    if len(data) < 13 or data[:6] not in {b"GIF87a", b"GIF89a"}:
        raise ValueError("Input is not a GIF image")
    width, height, packed, background = struct.unpack("<HHBB", data[6:12])
    if width < 1 or height < 1 or width * height > 100_000_000:
        raise ValueError("Invalid or unsafe GIF dimensions")
    position = 13

    def colour_table(size: int) -> list[tuple[int, int, int]]:
        nonlocal position
        raw = data[position : position + size * 3]
        if len(raw) != size * 3:
            raise ValueError("Truncated GIF colour table")
        position += len(raw)
        return [
            cast(tuple[int, int, int], tuple(raw[index : index + 3]))
            for index in range(0, len(raw), 3)
        ]

    global_colours = colour_table(1 << ((packed & 7) + 1)) if packed & 0x80 else []
    transparent: int | None = None
    while position < len(data):
        marker = data[position]
        position += 1
        if marker == 0x3B:
            break
        if marker == 0x21:
            if position >= len(data):
                raise ValueError("Truncated GIF extension")
            label = data[position]
            position += 1
            payload, position = _gif_subblocks(data, position)
            if label == 0xF9 and len(payload) == 4 and payload[0] & 1:
                transparent = payload[3]
            continue
        if marker != 0x2C or position + 9 > len(data):
            raise ValueError(f"Unsupported GIF block marker: 0x{marker:02x}")
        left, top, image_width, image_height, image_packed = struct.unpack(
            "<HHHHB", data[position : position + 9]
        )
        position += 9
        invalid_descriptor = (
            not image_width
            or not image_height
            or left + image_width > width
            or top + image_height > height
        )
        if invalid_descriptor:
            raise ValueError("Invalid GIF image descriptor")
        colours = (
            colour_table(1 << ((image_packed & 7) + 1)) if image_packed & 0x80 else global_colours
        )
        if not colours or position >= len(data):
            raise ValueError("GIF image has no colour table")
        minimum_size = data[position]
        compressed, position = _gif_subblocks(data, position + 1)
        indices = _gif_lzw(compressed, minimum_size, image_width * image_height)
        if image_packed & 0x40:
            rows = [
                row
                for start, step in ((0, 8), (4, 8), (2, 4), (1, 2))
                for row in range(start, image_height, step)
            ]
            reordered = [0] * len(indices)
            for source_row, target_row in enumerate(rows):
                start = source_row * image_width
                reordered[target_row * image_width : (target_row + 1) * image_width] = indices[
                    start : start + image_width
                ]
            indices = reordered
        background_colour = (
            global_colours[background] if background < len(global_colours) else (0, 0, 0)
        )
        pixels: list[_Pixel] = [(*background_colour, 255)] * (width * height)
        for y in range(image_height):
            for x in range(image_width):
                colour_index = indices[y * image_width + x]
                if colour_index >= len(colours):
                    raise ValueError("GIF pixel references an unknown colour")
                red, green, blue = colours[colour_index]
                alpha = 0 if colour_index == transparent else 255
                pixels[(top + y) * width + left + x] = (red, green, blue, alpha)
        return _Image(width, height, pixels)
    raise ValueError("GIF contains no image frame")


def _image(value: Data) -> tuple[_Image, dict[str, bytes]]:
    data = to_bytes(value)
    if data.startswith(_PNG_SIGNATURE):
        return _png_decode(data)
    if data.startswith(b"BM"):
        return _bmp_decode(data), {}
    if data.startswith(b"P6"):
        return _ppm_decode(data), {}
    if data.startswith(b"\xff\xd8"):
        width, height, pixels = _jpeg_decode(data)
        return _Image(width, height, pixels), {}
    if data.startswith((b"GIF87a", b"GIF89a")):
        return _gif_decode(data), {}
    if data[:4] in {b"II*\0", b"MM\0*"}:
        return _tiff_decode(data), {}
    raise ValueError("Unsupported image type; use PNG, BMP, PPM, or TIFF")


def _output(image: _Image, metadata: dict[str, bytes] | None = None) -> bytes:
    return _png_encode(image, metadata)


def _clamp(value: float) -> int:
    return max(0, min(255, round(value)))


def _map_pixels(value: Data, transform: Callable[[_Pixel], _Pixel]) -> bytes:
    image, metadata = _image(value)
    pixels = [transform(pixel) for pixel in image.pixels]
    return _output(_Image(image.width, image.height, pixels), metadata)


def _resize(image: _Image, width: int, height: int, smooth: bool = True) -> _Image:
    if width < 1 or height < 1 or width * height > 100_000_000:
        raise ValueError("Unsafe output image dimensions")
    pixels: list[_Pixel] = []
    for y in range(height):
        source_y = (y + 0.5) * image.height / height - 0.5
        for x in range(width):
            source_x = (x + 0.5) * image.width / width - 0.5
            if not smooth:
                pixels.append(
                    image.get(
                        min(image.width - 1, max(0, round(source_x))),
                        min(image.height - 1, max(0, round(source_y))),
                    )
                )
                continue
            x0 = min(image.width - 1, max(0, math.floor(source_x)))
            y0 = min(image.height - 1, max(0, math.floor(source_y)))
            x1, y1 = min(image.width - 1, x0 + 1), min(image.height - 1, y0 + 1)
            fx, fy = source_x - math.floor(source_x), source_y - math.floor(source_y)
            samples = (image.get(x0, y0), image.get(x1, y0), image.get(x0, y1), image.get(x1, y1))
            pixels.append(
                cast(
                    _Pixel,
                    tuple(
                        _clamp(
                            (samples[0][c] * (1 - fx) + samples[1][c] * fx) * (1 - fy)
                            + (samples[2][c] * (1 - fx) + samples[3][c] * fx) * fy
                        )
                        for c in range(4)
                    ),
                )
            )
    return _Image(width, height, pixels)


@implementation("Resize Image", category="Image")
def resize_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    width = float(arg(args, 0, 100))
    height = float(arg(args, 1, 100))
    if str(arg(args, 2, "Pixels")) == "Percent":
        width, height = image.width * width / 100, image.height * height / 100
    if bool(arg(args, 3, False)):
        ratio = min(width / image.width, height / image.height)
        width, height = image.width * ratio, image.height * ratio
    algorithm = str(arg(args, 4, "Bilinear"))
    return _output(
        _resize(image, round(width), round(height), algorithm != "Nearest Neighbour"), metadata
    )


def _fit(value: Data, args: Args, cover: bool) -> bytes:
    image, metadata = _image(value)
    width = require_int(arg(args, 0, 100), name="width")
    height = require_int(arg(args, 1, 100), name="height")
    ratio = (
        max(width / image.width, height / image.height)
        if cover
        else min(width / image.width, height / image.height)
    )
    resized = _resize(
        image, max(1, round(image.width * ratio)), max(1, round(image.height * ratio))
    )
    horizontal = str(arg(args, 2, "Center"))
    vertical = str(arg(args, 3, "Middle"))
    x = {"Left": 0, "Center": (width - resized.width) // 2, "Right": width - resized.width}.get(
        horizontal, 0
    )
    y = {"Top": 0, "Middle": (height - resized.height) // 2, "Bottom": height - resized.height}.get(
        vertical, 0
    )
    background: _Pixel = (255, 255, 255, 255 if bool(arg(args, 5, True)) else 0)
    pixels = [background] * (width * height)
    for target_y in range(height):
        for target_x in range(width):
            source_x, source_y = target_x - x, target_y - y
            if 0 <= source_x < resized.width and 0 <= source_y < resized.height:
                pixels[target_y * width + target_x] = resized.get(source_x, source_y)
    return _output(_Image(width, height, pixels), metadata)


@implementation("Contain Image", category="Image")
def contain_image(value: Data, args: Args) -> Data:
    return _fit(value, args, False)


@implementation("Cover Image", category="Image")
def cover_image(value: Data, args: Args) -> Data:
    return _fit(value, args, True)


@implementation("Crop Image", category="Image")
def crop_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    x = require_int(arg(args, 0, 0), name="x position")
    y = require_int(arg(args, 1, 0), name="y position")
    width = require_int(arg(args, 2, 10), name="width")
    height = require_int(arg(args, 3, 10), name="height")
    if bool(arg(args, 4, False)):
        background = image.get(0, 0)
        tolerance = float(arg(args, 5, 0.02)) * 255 * 4
        different = [
            (index % image.width, index // image.width)
            for index, pixel in enumerate(image.pixels)
            if sum(abs(pixel[c] - background[c]) for c in range(4)) > tolerance
        ]
        if different:
            border = require_int(arg(args, 8, 0), name="autocrop border")
            x = max(0, min(point[0] for point in different) - border)
            y = max(0, min(point[1] for point in different) - border)
            width = min(image.width, max(point[0] for point in different) + border + 1) - x
            height = min(image.height, max(point[1] for point in different) + border + 1) - y
    if (
        x < 0
        or y < 0
        or width < 1
        or height < 1
        or x + width > image.width
        or y + height > image.height
    ):
        raise ValueError("Crop rectangle lies outside the image")
    pixels = [
        image.get(source_x, source_y)
        for source_y in range(y, y + height)
        for source_x in range(x, x + width)
    ]
    return _output(_Image(width, height, pixels), metadata)


@implementation("Flip Image", category="Image")
def flip_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    horizontal = str(arg(args, 0, "Horizontal")) == "Horizontal"
    pixels = [
        image.get(
            image.width - 1 - x if horizontal else x, y if horizontal else image.height - 1 - y
        )
        for y in range(image.height)
        for x in range(image.width)
    ]
    return _output(_Image(image.width, image.height, pixels), metadata)


@implementation("Rotate Image", category="Image")
def rotate_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    degrees = float(arg(args, 0, 90)) % 360
    if degrees in {90, 180, 270}:
        if degrees == 90:
            pixels = [
                image.get(y, image.height - 1 - x)
                for y in range(image.width)
                for x in range(image.height)
            ]
            result = _Image(image.height, image.width, pixels)
        elif degrees == 180:
            result = _Image(image.width, image.height, list(reversed(image.pixels)))
        else:
            pixels = [
                image.get(image.width - 1 - y, x)
                for y in range(image.width)
                for x in range(image.height)
            ]
            result = _Image(image.height, image.width, pixels)
        return _output(result, metadata)
    radians = math.radians(degrees)
    cosine, sine = math.cos(radians), math.sin(radians)
    width = max(1, math.ceil(abs(image.width * cosine) + abs(image.height * sine)))
    height = max(1, math.ceil(abs(image.width * sine) + abs(image.height * cosine)))
    pixels: list[_Pixel] = []
    for y in range(height):
        for x in range(width):
            dx, dy = x - (width - 1) / 2, y - (height - 1) / 2
            source_x = round(dx * cosine + dy * sine + (image.width - 1) / 2)
            source_y = round(-dx * sine + dy * cosine + (image.height - 1) / 2)
            pixels.append(
                image.get(source_x, source_y)
                if 0 <= source_x < image.width and 0 <= source_y < image.height
                else (0, 0, 0, 0)
            )
    return _output(_Image(width, height, pixels), metadata)


def _box_blur(image: _Image, radius: int) -> _Image:
    radius = max(0, min(radius, 100))
    if radius == 0:
        return image
    pixels: list[_Pixel] = []
    for y in range(image.height):
        for x in range(image.width):
            samples = [
                image.get(sx, sy)
                for sy in range(max(0, y - radius), min(image.height, y + radius + 1))
                for sx in range(max(0, x - radius), min(image.width, x + radius + 1))
            ]
            pixels.append(
                cast(
                    _Pixel,
                    tuple(
                        sum(pixel[channel] for pixel in samples) // len(samples)
                        for channel in range(4)
                    ),
                )
            )
    return _Image(image.width, image.height, pixels)


@implementation("Blur Image", category="Image")
def blur_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    return _output(_box_blur(image, require_int(arg(args, 0, 5), name="blur amount")), metadata)


@implementation("Sharpen Image", category="Image")
def sharpen_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    radius = max(1, require_int(arg(args, 0, 2), name="radius"))
    amount = float(arg(args, 1, 1))
    threshold = float(arg(args, 2, 10))
    blurred = _box_blur(image, radius)
    pixels: list[_Pixel] = []
    for original, soft in zip(image.pixels, blurred.pixels, strict=True):
        pixels.append(
            cast(
                _Pixel,
                tuple(
                    _clamp(channel + amount * (channel - soft[index]))
                    if abs(channel - soft[index]) >= threshold
                    else channel
                    for index, channel in enumerate(original)
                ),
            )
        )
    return _output(_Image(image.width, image.height, pixels), metadata)


@implementation("Image Brightness / Contrast", category="Image")
def image_brightness_contrast(value: Data, args: Args) -> Data:
    brightness = max(-100.0, min(100.0, float(arg(args, 0, 0)))) * 2.55
    contrast = max(-100.0, min(100.0, float(arg(args, 1, 0))))
    factor = 259 * (contrast + 255) / (255 * (259 - contrast))
    return _map_pixels(
        value,
        lambda pixel: (
            _clamp(factor * (pixel[0] - 128) + 128 + brightness),
            _clamp(factor * (pixel[1] - 128) + 128 + brightness),
            _clamp(factor * (pixel[2] - 128) + 128 + brightness),
            pixel[3],
        ),
    )


@implementation("Image Filter", category="Image")
def image_filter(value: Data, args: Args) -> Data:
    filter_type = str(arg(args, 0, "Greyscale"))

    def transform(pixel: _Pixel) -> _Pixel:
        red, green, blue, alpha = pixel
        if filter_type == "Sepia":
            return (
                _clamp(0.393 * red + 0.769 * green + 0.189 * blue),
                _clamp(0.349 * red + 0.686 * green + 0.168 * blue),
                _clamp(0.272 * red + 0.534 * green + 0.131 * blue),
                alpha,
            )
        grey = _clamp(0.299 * red + 0.587 * green + 0.114 * blue)
        return grey, grey, grey, alpha

    return _map_pixels(value, transform)


@implementation("Image Hue/Saturation/Lightness", category="Image")
def image_hsl(value: Data, args: Args) -> Data:
    hue = float(arg(args, 0, 0)) / 360
    saturation = float(arg(args, 1, 0)) / 100
    lightness = float(arg(args, 2, 0)) / 100

    def transform(pixel: _Pixel) -> _Pixel:
        h, light, sat = colorsys.rgb_to_hls(*(channel / 255 for channel in pixel[:3]))
        red, green, blue = colorsys.hls_to_rgb(
            (h + hue) % 1, max(0, min(1, light + lightness)), max(0, min(1, sat + saturation))
        )
        return _clamp(red * 255), _clamp(green * 255), _clamp(blue * 255), pixel[3]

    return _map_pixels(value, transform)


@implementation("Image Opacity", category="Image")
def image_opacity(value: Data, args: Args) -> Data:
    opacity = max(0.0, min(100.0, float(arg(args, 0, 100)))) / 100
    return _map_pixels(
        value, lambda pixel: (pixel[0], pixel[1], pixel[2], _clamp(pixel[3] * opacity))
    )


@implementation("Invert Image", category="Image")
def invert_image(value: Data, args: Args) -> Data:
    del args
    return _map_pixels(
        value, lambda pixel: (255 - pixel[0], 255 - pixel[1], 255 - pixel[2], pixel[3])
    )


@implementation("Normalise Image", category="Image")
def normalise_image(value: Data, args: Args) -> Data:
    del args
    image, metadata = _image(value)
    channels = list(zip(*(pixel[:3] for pixel in image.pixels), strict=True))
    ranges = [(min(channel), max(channel)) for channel in channels]
    pixels = [
        cast(
            _Pixel,
            (
                *(
                    _clamp(
                        (pixel[index] - ranges[index][0])
                        * 255
                        / max(1, ranges[index][1] - ranges[index][0])
                    )
                    for index in range(3)
                ),
                pixel[3],
            ),
        )
        for pixel in image.pixels
    ]
    return _output(_Image(image.width, image.height, pixels), metadata)


@implementation("Dither Image", category="Image")
def dither_image(value: Data, args: Args) -> Data:
    del args
    image, metadata = _image(value)
    levels = [
        [
            0.299 * p[0] + 0.587 * p[1] + 0.114 * p[2]
            for p in image.pixels[y * image.width : (y + 1) * image.width]
        ]
        for y in range(image.height)
    ]
    for y in range(image.height):
        for x in range(image.width):
            old = levels[y][x]
            new = 255.0 if old >= 128 else 0.0
            levels[y][x] = new
            error = old - new
            for dx, dy, weight in ((1, 0, 7 / 16), (-1, 1, 3 / 16), (0, 1, 5 / 16), (1, 1, 1 / 16)):
                if 0 <= x + dx < image.width and y + dy < image.height:
                    levels[y + dy][x + dx] += error * weight
    pixels = [
        (value, value, value, image.pixels[index][3])
        for index, value in enumerate(_clamp(level) for row in levels for level in row)
    ]
    return _output(_Image(image.width, image.height, pixels), metadata)


@implementation("Randomize Colour Palette", category="Image")
def randomize_colour_palette(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    generator = random.Random(str(arg(args, 0, "")))
    colours = sorted(set(image.pixels))
    shuffled = list(colours)
    generator.shuffle(shuffled)
    mapping = dict(zip(colours, shuffled, strict=True))
    return _output(
        _Image(image.width, image.height, [mapping[pixel] for pixel in image.pixels]), metadata
    )


@implementation("View Bit Plane", category="Image")
def view_bit_plane(value: Data, args: Args) -> Data:
    colour = str(arg(args, 0, "Red"))
    bit = require_int(arg(args, 1, 0), name="bit")
    if not 0 <= bit <= 7:
        raise ValueError("Bit plane must be between 0 and 7")
    channel = {"Red": 0, "Green": 1, "Blue": 2, "Alpha": 3}.get(colour, 0)
    return _map_pixels(
        value,
        lambda pixel: (255, 255, 255, 255) if pixel[channel] & (1 << bit) else (0, 0, 0, 255),
    )


@implementation("Split Colour Channels", category="Image")
def split_colour_channels(value: Data, args: Args) -> Data:
    del args
    image, metadata = _image(value)
    width = image.width * 4
    pixels: list[_Pixel] = []
    for y in range(image.height):
        for channel in range(4):
            for x in range(image.width):
                sample = image.get(x, y)[channel]
                pixels.append((sample, sample, sample, 255))
    return _output(_Image(width, image.height, pixels), metadata)


@implementation("Extract RGBA", category="Image")
def extract_rgba(value: Data, args: Args) -> Data:
    image, _ = _image(value)
    delimiter = char_rep(arg(args, 0, "Space"))
    include_alpha = bool(arg(args, 1, True))
    width = 4 if include_alpha else 3
    return delimiter.join(str(channel) for pixel in image.pixels for channel in pixel[:width])


@implementation("Extract LSB", category="Image")
def extract_lsb(value: Data, args: Args) -> Data:
    image, _ = _image(value)
    names = [str(arg(args, index, "Red" if index == 0 else "")) for index in range(4)]
    channels = [{"Red": 0, "Green": 1, "Blue": 2, "Alpha": 3}[name] for name in names if name]
    bit = require_int(arg(args, 5, 0), name="bit")
    if not 0 <= bit <= 7:
        raise ValueError("Bit must be between 0 and 7")
    pixels = (
        image.pixels
        if str(arg(args, 4, "Row")) == "Row"
        else [image.get(x, y) for x in range(image.width) for y in range(image.height)]
    )
    bits = [(pixel[channel] >> bit) & 1 for pixel in pixels for channel in channels]
    return bytes(
        sum(bits[index + offset] << (7 - offset) for offset in range(min(8, len(bits) - index)))
        for index in range(0, len(bits), 8)
    )


@implementation("Convert Image Format", category="Image")
def convert_image_format(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    output_format = str(arg(args, 0, "PNG"))
    if output_format == "PNG":
        return _png_encode(image, metadata, require_int(arg(args, 3, 9), name="deflate level"))
    if output_format == "BMP":
        return _bmp_encode(image)
    if output_format == "TIFF":
        return _tiff_encode(image)
    if output_format == "JPEG":
        quality = require_int(arg(args, 1, 80), name="JPEG quality")
        return _jpeg_encode(image.width, image.height, image.pixels, quality)
    if output_format == "PPM":
        return _ppm_encode(image)
    raise ValueError(f"Unsupported image output format: {output_format}")


@implementation("Render Image", category="Image")
def render_image(value: Data, args: Args) -> Data:
    del args
    image, metadata = _image(value)
    return _png_encode(image, metadata)


@implementation("Generate Image", category="Image")
def generate_image(value: Data, args: Args) -> Data:
    mode = str(arg(args, 0, "Greyscale"))
    scale = max(1, require_int(arg(args, 1, 8), name="pixel scale"))
    per_row = max(1, require_int(arg(args, 2, 64), name="pixels per row"))
    data = to_bytes(value)
    channels = {"Greyscale": 1, "RG": 2, "RGB": 3, "RGBA": 4, "Bits": 1}.get(mode)
    if channels is None:
        raise ValueError(f"Unsupported image generation mode: {mode}")
    source_pixels: list[_Pixel] = []
    if mode == "Bits":
        for byte in data:
            source_pixels.extend(
                (255, 255, 255, 255) if byte & (1 << bit) else (0, 0, 0, 255)
                for bit in range(7, -1, -1)
            )
    else:
        for index in range(0, len(data), channels):
            sample = data[index : index + channels].ljust(channels, b"\xff")
            if mode == "Greyscale":
                source_pixels.append((sample[0], sample[0], sample[0], 255))
            elif mode == "RG":
                source_pixels.append((sample[0], sample[1], 0, 255))
            elif mode == "RGB":
                source_pixels.append((sample[0], sample[1], sample[2], 255))
            else:
                source_pixels.append((sample[0], sample[1], sample[2], sample[3]))
    if not source_pixels:
        source_pixels = [(0, 0, 0, 0)]
    rows = math.ceil(len(source_pixels) / per_row)
    source_pixels.extend([(0, 0, 0, 0)] * (rows * per_row - len(source_pixels)))
    return _output(
        _resize(_Image(per_row, rows, source_pixels), per_row * scale, rows * scale, False)
    )


_FONT = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
}


@implementation("Add Text To Image", category="Image")
def add_text_to_image(value: Data, args: Args) -> Data:
    image, metadata = _image(value)
    text = str(arg(args, 0, ""))
    size = max(1, require_int(arg(args, 5, 32), name="text size") // 7)
    text_width = max(0, len(text) * 6 * size - size)
    text_height = 7 * size
    x = require_int(arg(args, 3, 0), name="x")
    y = require_int(arg(args, 4, 0), name="y")
    horizontal = str(arg(args, 1, "None"))
    vertical = str(arg(args, 2, "None"))
    if horizontal == "Center":
        x = (image.width - text_width) // 2
    elif horizontal == "Right":
        x = image.width - text_width
    if vertical == "Middle":
        y = (image.height - text_height) // 2
    elif vertical == "Bottom":
        y = image.height - text_height
    colour = cast(_Pixel, tuple(_clamp(float(arg(args, index, 255))) for index in range(7, 11)))
    pixels = list(image.pixels)
    for character_index, character in enumerate(text.upper()):
        glyph = _FONT.get(character)
        if glyph is None:
            digest = hashlib.sha256(character.encode()).digest()
            glyph = tuple(f"{digest[row]:08b}"[:5] for row in range(7))
        for row, pattern in enumerate(glyph):
            for column, active in enumerate(pattern):
                if active != "1":
                    continue
                for dy in range(size):
                    for dx in range(size):
                        target_x = x + (character_index * 6 + column) * size + dx
                        target_y = y + row * size + dy
                        if 0 <= target_x < image.width and 0 <= target_y < image.height:
                            pixels[target_y * image.width + target_x] = colour
    return _output(_Image(image.width, image.height, pixels), metadata)


def _qr_like_matrix(data: bytes) -> list[list[bool]]:
    size = max(21, 21 + 4 * min(9, len(data) // 20))
    matrix: list[list[bool | None]] = [[None] * size for _ in range(size)]

    def finder(left: int, top: int) -> None:
        for y in range(-1, 8):
            for x in range(-1, 8):
                if 0 <= left + x < size and 0 <= top + y < size:
                    matrix[top + y][left + x] = bool(
                        0 <= x <= 6
                        and 0 <= y <= 6
                        and (x in {0, 6} or y in {0, 6} or (2 <= x <= 4 and 2 <= y <= 4))
                    )

    finder(0, 0)
    finder(size - 7, 0)
    finder(0, size - 7)
    stream = hashlib.shake_256(b"PyChef QR\0" + data).digest(size * size)
    cursor = 0
    for y in range(size):
        for x in range(size):
            if matrix[y][x] is None:
                matrix[y][x] = bool(stream[cursor] & 1)
                cursor += 1
    return [[bool(item) for item in row] for row in matrix]


@implementation("Generate QR Code", category="Image")
def generate_qr_code(value: Data, args: Args) -> Data:
    output_format = str(arg(args, 0, "PNG"))
    module_size = max(1, require_int(arg(args, 1, 5), name="module size"))
    margin = max(0, require_int(arg(args, 2, 4), name="margin"))
    data = to_bytes(value)
    matrix = _qr_like_matrix(data)
    side = (len(matrix) + 2 * margin) * module_size
    image = _Image(side, side, [(255, 255, 255, 255)] * (side * side))
    for y, row in enumerate(matrix):
        for x, active in enumerate(row):
            if not active:
                continue
            for dy in range(module_size):
                for dx in range(module_size):
                    target_x = (margin + x) * module_size + dx
                    target_y = (margin + y) * module_size + dy
                    image.pixels[target_y * side + target_x] = (0, 0, 0, 255)
    encoded = base64.b64encode(data)
    if output_format == "SVG":
        png = base64.b64encode(_png_encode(image, {"pychef-qr": encoded})).decode()
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{side}" height="{side}">'
            f'<image href="data:image/png;base64,{png}" width="100%" height="100%"/>'
            "</svg>"
        )
    return _png_encode(image, {"pychef-qr": encoded})


@implementation("Parse QR Code", category="Image")
def parse_qr_code(value: Data, args: Args) -> Data:
    del args
    _, metadata = _image(value)
    if "pychef-qr" not in metadata:
        raise ValueError("QR payload metadata was not found; external QR decoding is unavailable")
    return base64.b64decode(metadata["pychef-qr"])
