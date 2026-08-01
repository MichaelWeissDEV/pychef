"""Pure standard-library compression and archive operations."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zipfile
import zlib

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg, require_int


def _strategy(name: str) -> int:
    return {
        "Dynamic Huffman Coding": zlib.Z_DEFAULT_STRATEGY,
        "Fixed Huffman Coding": zlib.Z_FIXED,
        "Huffman Only": zlib.Z_HUFFMAN_ONLY,
        "Run Length Encoding": zlib.Z_RLE,
        "Filtered": zlib.Z_FILTERED,
    }.get(name, zlib.Z_DEFAULT_STRATEGY)


@implementation("Gzip", category="Compression")
def gzip_compress(value: Data, args: Args) -> bytes:
    compression_type = str(arg(args, 0, "Dynamic Huffman Coding"))
    filename = str(arg(args, 1, ""))
    comment = str(arg(args, 2, ""))
    include_header_checksum = bool(arg(args, 3, False))
    flags = (
        (0x08 if filename else 0)
        | (0x10 if comment else 0)
        | (0x02 if include_header_checksum else 0)
    )
    header = bytearray(b"\x1f\x8b\x08")
    header.append(flags)
    header.extend(b"\x00\x00\x00\x00\x00\xff")
    if filename:
        header.extend(filename.encode("latin-1", "replace") + b"\0")
    if comment:
        header.extend(comment.encode("latin-1", "replace") + b"\0")
    if include_header_checksum:
        header.extend(struct.pack("<H", zlib.crc32(header) & 0xFFFF))
    data = to_bytes(value)
    compressor = zlib.compressobj(
        level=6,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=8,
        strategy=_strategy(compression_type),
    )
    body = compressor.compress(data) + compressor.flush()
    trailer = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return bytes(header) + body + trailer


@implementation("Gunzip", category="Compression")
def gunzip(value: Data, _args: Args) -> bytes:
    return gzip.decompress(to_bytes(value))


@implementation("Zlib Deflate", category="Compression")
def zlib_deflate(value: Data, args: Args) -> bytes:
    strategy = _strategy(str(arg(args, 0, "Dynamic Huffman Coding")))
    compressor = zlib.compressobj(level=6, wbits=zlib.MAX_WBITS, strategy=strategy)
    return compressor.compress(to_bytes(value)) + compressor.flush()


@implementation("Zlib Inflate", category="Compression")
def zlib_inflate(value: Data, args: Args) -> bytes:
    start = require_int(arg(args, 0, 0), name="start index")
    return zlib.decompress(to_bytes(value)[start:], wbits=zlib.MAX_WBITS)


@implementation("Raw Deflate", category="Compression")
def raw_deflate(value: Data, args: Args) -> bytes:
    strategy = _strategy(str(arg(args, 0, "Dynamic Huffman Coding")))
    compressor = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS, strategy=strategy)
    return compressor.compress(to_bytes(value)) + compressor.flush()


@implementation("Raw Inflate", category="Compression")
def raw_inflate(value: Data, args: Args) -> bytes:
    start = require_int(arg(args, 0, 0), name="start index")
    return zlib.decompress(to_bytes(value)[start:], wbits=-zlib.MAX_WBITS)


@implementation("Bzip2 Compress", category="Compression")
def bzip2_compress(value: Data, args: Args) -> bytes:
    level = require_int(arg(args, 0, 9), name="block size")
    return bz2.compress(to_bytes(value), compresslevel=level)


@implementation("Bzip2 Decompress", category="Compression")
def bzip2_decompress(value: Data, _args: Args) -> bytes:
    return bz2.decompress(to_bytes(value))


@implementation("LZMA Compress", category="Compression")
def lzma_compress(value: Data, args: Args) -> bytes:
    preset = require_int(arg(args, 0, 6), name="preset")
    return lzma.compress(to_bytes(value), format=lzma.FORMAT_ALONE, preset=preset)


@implementation("LZMA Decompress", category="Compression")
def lzma_decompress(value: Data, _args: Args) -> bytes:
    return lzma.decompress(to_bytes(value), format=lzma.FORMAT_AUTO)


@implementation("Zip", category="Compression")
def zip_archive(value: Data, args: Args) -> bytes:
    filename = str(arg(args, 0, "file.txt"))
    comment = str(arg(args, 1, ""))
    password = arg(args, 2, "")
    method = str(arg(args, 3, "Deflate"))
    if password:
        raise ValueError("the Python standard library cannot create encrypted ZIP files")
    compression = zipfile.ZIP_DEFLATED if method == "Deflate" else zipfile.ZIP_STORED
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        info = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = compression
        info.comment = comment.encode("utf-8")
        archive.writestr(info, to_bytes(value))
        archive.comment = comment.encode("utf-8")
    return output.getvalue()


@implementation("Unzip", category="Compression")
def unzip_archive(value: Data, args: Args) -> bytes:
    password = str(arg(args, 0, ""))
    with zipfile.ZipFile(io.BytesIO(to_bytes(value))) as archive:
        files = [info for info in archive.infolist() if not info.is_dir()]
        if len(files) != 1:
            raise ValueError("library-mode Unzip requires an archive containing exactly one file")
        return archive.read(files[0], pwd=password.encode() if password else None)


@implementation("Tar", category="Compression")
def tar_archive(value: Data, args: Args) -> bytes:
    filename = str(arg(args, 0, "file.txt"))
    data = to_bytes(value)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo(filename)
        info.size = len(data)
        info.mtime = 0
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


@implementation("Untar", category="Compression")
def untar_archive(value: Data, _args: Args) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(to_bytes(value)), mode="r:*") as archive:
        files = [member for member in archive.getmembers() if member.isfile()]
        if len(files) != 1:
            raise ValueError("library-mode Untar requires an archive containing exactly one file")
        extracted = archive.extractfile(files[0])
        if extracted is None:
            raise ValueError("archive member could not be extracted")
        return extracted.read()
