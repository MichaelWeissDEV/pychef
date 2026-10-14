"""Compression helpers."""

from __future__ import annotations

from ._engine import BytesLike, as_bytes, run_operation


def gzip_compress(
    value: str | BytesLike,
    *,
    filename: str = "",
    comment: str = "",
    include_checksum: bool = False,
) -> bytes:
    """Compress with gzip headers (``Gzip``, dynamic Huffman coding)."""
    return as_bytes(
        run_operation(
            "Gzip", value, ("Dynamic Huffman Coding", filename, comment, include_checksum)
        )
    )


def gzip_decompress(value: BytesLike) -> bytes:
    """Decompress gzip data (``Gunzip``)."""
    return as_bytes(run_operation("Gunzip", value))
