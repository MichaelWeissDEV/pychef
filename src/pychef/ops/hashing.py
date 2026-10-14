"""Hash helpers.

These are the same functions as :func:`pychef.ctf.md5` and friends: one
implementation, one return format (lowercase hexadecimal ``str``). The wrappers
here only add type validation and the input-size limit of the active policy.
"""

from __future__ import annotations

from typing import Literal, overload

from ._engine import BytesLike, guard_input


@overload
def digest(
    value: str | BytesLike, *, algorithm: str = "sha256", output: Literal["hex", "base64"] = "hex"
) -> str: ...
@overload
def digest(
    value: str | BytesLike, *, algorithm: str = "sha256", output: Literal["raw", "bytes"]
) -> bytes: ...
def digest(
    value: str | BytesLike, *, algorithm: str = "sha256", output: str = "hex"
) -> str | bytes:
    """Hash with any :mod:`hashlib` algorithm; ``output`` is hex, base64, or raw bytes."""
    from ..ctf import digest as _digest

    return _digest(guard_input(value), algorithm=algorithm, output=output)


def md5(value: str | BytesLike) -> str:
    """Return the MD5 digest as lowercase hexadecimal text."""
    return digest(value, algorithm="md5")


def sha1(value: str | BytesLike) -> str:
    """Return the SHA-1 digest as lowercase hexadecimal text."""
    return digest(value, algorithm="sha1")


def sha256(value: str | BytesLike) -> str:
    """Return the SHA-256 digest as lowercase hexadecimal text."""
    return digest(value, algorithm="sha256")


def sha512(value: str | BytesLike) -> str:
    """Return the SHA-512 digest as lowercase hexadecimal text."""
    return digest(value, algorithm="sha512")
