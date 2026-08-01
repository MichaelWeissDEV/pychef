"""Dependency-free bitmap OCR for high-contrast printed Latin text."""

from __future__ import annotations

import hashlib
import math
import re

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg
from .image_ops import _FONT, _Image, _image


def _pbm(data: bytes) -> _Image:
    if data.startswith(b"P1"):
        tokens = re.findall(rb"[^\s#]+", re.sub(rb"#[^\r\n]*", b"", data))
        if len(tokens) < 3:
            raise ValueError("Invalid PBM image")
        width, height = int(tokens[1]), int(tokens[2])
        samples = [int(token) for token in tokens[3:]]
        if len(samples) != width * height or any(sample not in {0, 1} for sample in samples):
            raise ValueError("Invalid PBM pixel data")
    elif data.startswith(b"P4"):
        header = re.match(rb"P4\s+(?:#[^\r\n]*\s+)*(\d+)\s+(\d+)\s", data)
        if header is None:
            raise ValueError("Invalid PBM image")
        width, height = int(header.group(1)), int(header.group(2))
        stride = (width + 7) // 8
        raw = data[header.end() :]
        if len(raw) < stride * height:
            raise ValueError("Truncated PBM pixel data")
        samples = [
            (raw[y * stride + x // 8] >> (7 - x % 8)) & 1
            for y in range(height)
            for x in range(width)
        ]
    else:
        raise ValueError("Input is not a PBM image")
    return _Image(
        width,
        height,
        [(0, 0, 0, 255) if sample else (255, 255, 255, 255) for sample in samples],
    )


def _otsu(values: list[int]) -> int:
    histogram = [0] * 256
    for value in values:
        histogram[value] += 1
    total = len(values)
    weighted = sum(index * count for index, count in enumerate(histogram))
    background_weight = background_sum = 0
    best_variance = -1.0
    threshold = 127
    for index, count in enumerate(histogram):
        background_weight += count
        if not background_weight:
            continue
        foreground_weight = total - background_weight
        if not foreground_weight:
            break
        background_sum += index * count
        mean_background = background_sum / background_weight
        mean_foreground = (weighted - background_sum) / foreground_weight
        variance = background_weight * foreground_weight * (mean_background - mean_foreground) ** 2
        if variance > best_variance:
            best_variance, threshold = variance, index
    return threshold


def _runs(active: list[bool]) -> list[tuple[int, int]]:
    output: list[tuple[int, int]] = []
    start = -1
    for index, value in enumerate([*active, False]):
        if value and start < 0:
            start = index
        elif not value and start >= 0:
            output.append((start, index))
            start = -1
    return output


def _template(character: str) -> tuple[str, ...]:
    glyph = _FONT.get(character)
    if glyph is not None:
        return glyph
    digest = hashlib.sha256(character.encode()).digest()
    return tuple(f"{digest[row]:08b}"[:5] for row in range(7))


_TEMPLATES = {
    character: _template(character)
    for character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,:;!?-_+/()[]{}@#$%&*=<>"
}


def _sample(
    binary: list[list[bool]], left: int, right: int, top: int, bottom: int
) -> tuple[str, ...]:
    output = []
    for row in range(7):
        y0 = top + row * (bottom - top) / 7
        y1 = top + (row + 1) * (bottom - top) / 7
        line = ""
        for column in range(5):
            x0 = left + column * (right - left) / 5
            x1 = left + (column + 1) * (right - left) / 5
            points = [
                binary[y][x]
                for y in range(max(top, math.floor(y0)), min(bottom, math.ceil(y1)))
                for x in range(max(left, math.floor(x0)), min(right, math.ceil(x1)))
            ]
            line += "1" if points and sum(points) >= len(points) / 3 else "0"
        output.append(line)
    return tuple(output)


def _recognize_glyph(glyph: tuple[str, ...]) -> tuple[str, float]:
    best_character = "?"
    best_score = -1.0
    for character, template in _TEMPLATES.items():
        equal = sum(
            left == right
            for row, expected in zip(glyph, template, strict=True)
            for left, right in zip(row, expected, strict=True)
        )
        score = equal / 35
        if score > best_score:
            best_character, best_score = character, score
    return best_character, best_score


def _ocr(image: _Image) -> tuple[str, float]:
    greys = [
        round(0.299 * red + 0.587 * green + 0.114 * blue) for red, green, blue, _ in image.pixels
    ]
    threshold = _otsu(greys)
    dark = [value <= threshold for value in greys]
    border = [
        dark[y * image.width + x]
        for y in range(image.height)
        for x in range(image.width)
        if x in {0, image.width - 1} or y in {0, image.height - 1}
    ]
    invert = bool(border) and sum(border) > len(border) / 2
    binary = [
        [dark[y * image.width + x] ^ invert for x in range(image.width)]
        for y in range(image.height)
    ]
    row_runs = _runs([any(row) for row in binary])
    if not row_runs:
        return "", 100.0
    lines: list[str] = []
    confidences: list[float] = []
    for top, bottom in row_runs:
        columns = [any(binary[y][x] for y in range(top, bottom)) for x in range(image.width)]
        column_runs = _runs(columns)
        if not column_runs:
            continue
        heights = bottom - top
        estimated_scale = max(1, round(heights / 7))
        characters: list[str] = []
        previous_right = column_runs[0][0]
        for left, right in column_runs:
            gap = left - previous_right
            if characters and gap >= estimated_scale * 4:
                characters.append(" ")
            width = right - left
            count = max(1, round((width + estimated_scale) / (6 * estimated_scale)))
            if count == 1:
                glyph = _sample(binary, left, right, top, bottom)
                character, confidence = _recognize_glyph(glyph)
                characters.append(character)
                confidences.append(confidence)
            else:
                cell = width / count
                for index in range(count):
                    cell_left = round(left + index * cell)
                    cell_right = round(left + (index + 1) * cell - estimated_scale / 6)
                    glyph = _sample(binary, cell_left, max(cell_left + 1, cell_right), top, bottom)
                    character, confidence = _recognize_glyph(glyph)
                    characters.append(character)
                    confidences.append(confidence)
            previous_right = right
        lines.append("".join(characters))
    return "\n".join(lines), (100 * sum(confidences) / len(confidences) if confidences else 0.0)


@implementation("Optical Character Recognition", category="OCR")
def optical_character_recognition(value: Data, args: Args) -> str:
    data = to_bytes(value)
    try:
        image = _pbm(data) if data.startswith((b"P1", b"P4")) else _image(data)[0]
    except ValueError as exc:
        raise ValueError(
            "Unsupported file type (supported: png,bmp,pbm,ppm) or no file provided"
        ) from exc
    text, confidence = _ocr(image)
    if bool(arg(args, 0, True)):
        return f"Confidence: {confidence:.6g}%\n\n{text}"
    return text
