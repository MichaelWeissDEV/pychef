"""Tests for the dependency-free raster image operation family."""

from __future__ import annotations

import base64
import struct
import zlib
from collections.abc import Sequence
from typing import Any

import pytest

from pychef import registry
from pychef.operations import image_ops


def run(name: str, value: str | bytes, args: Sequence[Any] | None = None) -> Any:
    return registry.get(name).run(value, args or [])


@pytest.fixture(scope="module")
def rgba_png() -> bytes:
    raw = bytes(
        channel
        for index in range(12)
        for channel in (index * 20 % 256, index * 40 % 256, index * 60 % 256, 128 + index)
    )
    result = run("Generate Image", raw, ["RGBA", 1, 4])
    assert isinstance(result, bytes)
    return result


def dimensions(value: str | bytes) -> tuple[int, int]:
    image, _ = image_ops._image(value)
    return image.width, image.height


@pytest.mark.parametrize(
    ("mode", "data"),
    [
        ("Greyscale", b"\0\x7f\xff"),
        ("RG", b"\x01\x02\x03\x04"),
        ("RGB", b"\x01\x02\x03\x04\x05\x06"),
        ("RGBA", b"\x01\x02\x03\x04"),
        ("Bits", b"\xa5"),
    ],
)
def test_generate_image_modes(mode: str, data: bytes) -> None:
    generated = run("Generate Image", data, [mode, 2, 4])
    image, _ = image_ops._image(generated)
    assert image.width == 8 and image.height >= 2


def test_png_decodes_all_filter_and_colour_types() -> None:
    for filter_type in range(5):
        header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
        png = image_ops._PNG_SIGNATURE
        png += image_ops._chunk(b"IHDR", header)
        png += image_ops._chunk(b"IDAT", zlib.compress(bytes([filter_type, 1, 2, 3, 4])))
        png += image_ops._chunk(b"IEND", b"")
        assert image_ops._png_decode(png)[0].pixels == [(1, 2, 3, 4)]
    for colour_type, raw, expected in (
        (0, b"\x07", (7, 7, 7, 255)),
        (2, b"\x01\x02\x03", (1, 2, 3, 255)),
        (4, b"\x07\x08", (7, 7, 7, 8)),
    ):
        header = struct.pack(">IIBBBBB", 1, 1, 8, colour_type, 0, 0, 0)
        png = image_ops._PNG_SIGNATURE + image_ops._chunk(b"IHDR", header)
        png += image_ops._chunk(b"IDAT", zlib.compress(b"\0" + raw)) + image_ops._chunk(
            b"IEND", b""
        )
        assert image_ops._png_decode(png)[0].pixels == [expected]


def test_resize_contain_cover_and_crop(rgba_png: bytes) -> None:
    assert dimensions(run("Resize Image", rgba_png, [8, 6, "Pixels", False, "Bilinear"])) == (
        8,
        6,
    )
    assert dimensions(
        run("Resize Image", rgba_png, [50, 50, "Percent", True, "Nearest Neighbour"])
    ) == (2, 2)
    assert dimensions(run("Contain Image", rgba_png, [10, 10, "Center", "Middle"])) == (
        10,
        10,
    )
    assert dimensions(run("Cover Image", rgba_png, [5, 5, "Right", "Bottom"])) == (5, 5)
    assert dimensions(run("Crop Image", rgba_png, [1, 1, 2, 2])) == (2, 2)

    bordered = image_ops._Image(5, 5, [(255, 255, 255, 255)] * 25)
    bordered.pixels[12] = (0, 0, 0, 255)
    autocropped = run(
        "Crop Image", image_ops._png_encode(bordered), [0, 0, 1, 1, True, 0, True, False, 1]
    )
    assert dimensions(autocropped) == (3, 3)


@pytest.mark.parametrize("axis", ["Horizontal", "Vertical"])
def test_flip_image(rgba_png: bytes, axis: str) -> None:
    flipped = run("Flip Image", rgba_png, [axis])
    assert dimensions(flipped) == (4, 3)
    assert run("Flip Image", flipped, [axis]) == rgba_png


@pytest.mark.parametrize(
    ("angle", "expected"), [(90, (3, 4)), (180, (4, 3)), (270, (3, 4)), (45, (5, 5))]
)
def test_rotate_image(rgba_png: bytes, angle: int, expected: tuple[int, int]) -> None:
    assert dimensions(run("Rotate Image", rgba_png, [angle])) == expected


def test_blur_sharpen_and_pixel_filters(rgba_png: bytes) -> None:
    assert run("Blur Image", rgba_png, [0]) == rgba_png
    for name, args in (
        ("Blur Image", [1, "Gaussian"]),
        ("Sharpen Image", [1, 1.5, 0]),
        ("Image Brightness / Contrast", [20, -10]),
        ("Image Filter", ["Greyscale"]),
        ("Image Filter", ["Sepia"]),
        ("Image Hue/Saturation/Lightness", [180, 20, -10]),
        ("Image Opacity", [50]),
        ("Invert Image", []),
        ("Normalise Image", []),
        ("Dither Image", []),
    ):
        transformed = run(name, rgba_png, args)
        assert dimensions(transformed) == (4, 3)


def test_palette_bit_planes_channels_and_extraction(rgba_png: bytes) -> None:
    first = run("Randomize Colour Palette", rgba_png, ["seed"])
    assert first == run("Randomize Colour Palette", rgba_png, ["seed"])
    for colour in ("Red", "Green", "Blue", "Alpha"):
        plane = run("View Bit Plane", rgba_png, [colour, 2])
        assert dimensions(plane) == (4, 3)
    split = run("Split Colour Channels", rgba_png)
    assert dimensions(split) == (16, 3)
    rgba = run("Extract RGBA", rgba_png, ["Comma", True])
    rgb = run("Extract RGBA", rgba_png, ["Colon", False])
    assert len(rgba.split(",")) == 48
    assert len(rgb.split(":")) == 36
    row_bits = run("Extract LSB", rgba_png, ["Red", "Green", "", "", "Row", 0])
    column_bits = run("Extract LSB", rgba_png, ["Blue", "", "", "", "Column", 1])
    assert isinstance(row_bits, bytes) and len(row_bits) == 3
    assert isinstance(column_bits, bytes) and len(column_bits) == 2


def test_format_conversion_png_bmp_ppm(rgba_png: bytes) -> None:
    png = run("Convert Image Format", rgba_png, ["PNG", 80, "None", 1])
    assert png.startswith(image_ops._PNG_SIGNATURE)
    bmp = run("Convert Image Format", rgba_png, ["BMP"])
    assert bmp.startswith(b"BM") and dimensions(bmp) == (4, 3)
    ppm = run("Convert Image Format", rgba_png, ["PPM"])
    assert ppm.startswith(b"P6") and dimensions(ppm) == (4, 3)
    fallback = run("Convert Image Format", rgba_png, ["JPEG"])
    assert fallback.startswith(b"P6")
    assert run("Render Image", bmp).startswith(image_ops._PNG_SIGNATURE)


def test_add_text_alignment(rgba_png: bytes) -> None:
    for horizontal, vertical in (("None", "None"), ("Center", "Middle"), ("Right", "Bottom")):
        rendered = run(
            "Add Text To Image",
            rgba_png,
            ["HELLO?", horizontal, vertical, 0, 0, 7, "Roboto", 255, 0, 0, 255],
        )
        assert dimensions(rendered) == (4, 3)


def test_qr_metadata_round_trip_and_svg() -> None:
    png = run("Generate QR Code", "Grüße", ["PNG", 2, 1, "Medium"])
    assert run("Parse QR Code", png) == "Grüße".encode()
    svg = run("Generate QR Code", "hello", ["SVG", 1, 0, "Low"])
    assert svg.startswith("<svg") and "data:image/png;base64," in svg
    plain = run("Generate Image", b"abc", ["RGB", 1, 1])
    with pytest.raises(ValueError):
        run("Parse QR Code", plain)


def test_image_validation_errors(rgba_png: bytes) -> None:
    with pytest.raises(ValueError):
        image_ops._image(b"not an image")
    with pytest.raises(ValueError):
        run("Crop Image", rgba_png, [-1, 0, 2, 2])
    with pytest.raises(ValueError):
        run("View Bit Plane", rgba_png, ["Red", 8])
    with pytest.raises(ValueError):
        run("Extract LSB", rgba_png, ["Red", "", "", "", "Row", -1])
    with pytest.raises(ValueError):
        run("Convert Image Format", rgba_png, ["GIF"])
    with pytest.raises(ValueError):
        run("Generate Image", b"x", ["Unknown"])


def test_data_uri_can_be_constructed_from_rendered_image(rgba_png: bytes) -> None:
    assert base64.b64decode(base64.b64encode(rgba_png)) == rgba_png
