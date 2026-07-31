"""Compression tests derived from CyberChef's operation suite."""

from __future__ import annotations

from pychef import bake


def test_bzip2_official_decompression_vector() -> None:
    source = (
        "425a6839314159265359b218ed630000031380400104002a438c00200021a9ea601a100032"
        "02185d5ed68ca6442f1e177245385090b218ed63"
    )
    result = bake(
        source,
        [
            {"op": "From Hex", "args": ["Space"]},
            {"op": "Bzip2 Decompress", "args": []},
        ],
        return_type="str",
    )
    assert result == "The cat sat on the mat."


def test_lzma_official_decompression_vector() -> None:
    source = (
        "5d00008000ffffffffffffffff002a1a08a202b1a4b814b912c94c4152e1641907d3fd8cd903ffff4fec0000"
    )
    assert (
        bake(source, ["From Hex", "LZMA Decompress"], return_type="str")
        == "The cat sat on the mat."
    )


def test_compression_round_trips() -> None:
    data = b"The quick brown fox jumped over the slow dog" * 20
    for compress, decompress in [
        ("Gzip", "Gunzip"),
        ("Zlib Deflate", "Zlib Inflate"),
        ("Raw Deflate", "Raw Inflate"),
        ("Bzip2 Compress", "Bzip2 Decompress"),
        ("LZMA Compress", "LZMA Decompress"),
    ]:
        assert bake(data, [compress, decompress]) == data


def test_gzip_metadata_round_trip() -> None:
    recipe = [
        {"op": "Gzip", "args": ["Fixed Huffman Coding", "file.txt", "comment", True]},
        "Gunzip",
    ]
    assert bake("hello hello hello", recipe) == b"hello hello hello"


def test_single_file_zip_and_tar_round_trips() -> None:
    assert bake(b"archive data", [{"op": "Zip", "args": ["a.txt"]}, "Unzip"]) == b"archive data"
    assert bake(b"archive data", [{"op": "Tar", "args": ["a.txt"]}, "Untar"]) == b"archive data"
