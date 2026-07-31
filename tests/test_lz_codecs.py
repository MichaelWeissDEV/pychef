"""Official CyberChef LZ-family vectors."""

from __future__ import annotations

import pytest

from pychef import bake


def test_lz4_official_vector() -> None:
    expected = bytes.fromhex(
        "04224d184070df170000805468652063617420736174206f6e20746865206d61742e00000000"
    )
    compressed = bake(b"The cat sat on the mat.", ["LZ4 Compress"])
    assert compressed == expected
    assert bake(compressed, ["LZ4 Decompress"]) == b"The cat sat on the mat."


def test_lz4_compressed_block_and_validation() -> None:
    frame = bytes.fromhex("04224d184070df0600000035616263030000000000")
    assert bake(frame, ["LZ4 Decompress"]) == b"abcabcabcabc"
    with pytest.raises(Exception, match="invalid LZ4 frame"):
        bake(b"invalid", ["LZ4 Decompress"])


def test_lzstring_official_base64_vector() -> None:
    compressed = bake("hello world", [{"op": "LZString Compress", "args": ["Base64"]}])
    assert compressed == "BYUwNmD2AEDukCcwBMg="
    assert bake(compressed, [{"op": "LZString Decompress", "args": ["Base64"]}]) == ("hello world")


@pytest.mark.parametrize("output_format", ["default", "UTF16", "Base64"])
def test_lzstring_all_formats_and_utf16_units(output_format: str) -> None:
    source = "Unicode: Grüße 🌍 — repeated repeated repeated"
    compressed = bake(source, [{"op": "LZString Compress", "args": [output_format]}])
    assert isinstance(compressed, str)
    assert bake(compressed, [{"op": "LZString Decompress", "args": [output_format]}]) == source


def test_lznt1_official_vector() -> None:
    source = b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot"
    assert bake(source, ["LZNT1 Decompress"]) == b"compressedtestdatacompressedalot"
