"""Dependency-free byte kernels shared by the CTF helpers and the operations."""

from __future__ import annotations


def xor_repeating(data: bytes, key: bytes) -> bytes:
    """XOR *data* with *key* repeated to the data length (C-speed, no per-byte loop)."""
    if not key:
        raise ValueError("XOR key must not be empty")
    size = len(data)
    if not size:
        return b""
    if len(key) == 1:
        table = bytes(value ^ key[0] for value in range(256))
        return data.translate(table)
    stream = (key * (size // len(key) + 1))[:size]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(size, "big")
