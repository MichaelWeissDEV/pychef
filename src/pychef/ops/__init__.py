"""Direct, policy-aware functions for common operations.

Use these helpers to run a single transformation without building a recipe or
pipeline::

    from pychef.ops import from_hex, to_base64

    to_base64(from_hex("414243"))  # 'QUJD'

Every helper runs the registered operation through the regular engine with the
:meth:`~pychef.ExecutionPolicy.safe` policy unless a policy is given via
:func:`using_policy` (or ``run_operation(..., policy=...)``). Network access is
therefore denied exactly as in :func:`pychef.bake`. Use :func:`run_operation` to
call any of the registered operations.
"""

from __future__ import annotations

from ._engine import run_operation, using_policy
from .bitwise import xor
from .compression import gzip_compress, gzip_decompress
from .encoding import from_base32, from_base64, from_hex, to_base32, to_base64, to_hex
from .hashing import digest, md5, sha1, sha256, sha512
from .text import html_decode, html_encode, reverse, rot13, url_decode, url_encode

__all__ = [
    "digest",
    "from_base32",
    "from_base64",
    "from_hex",
    "gzip_compress",
    "gzip_decompress",
    "html_decode",
    "html_encode",
    "md5",
    "reverse",
    "rot13",
    "run_operation",
    "sha1",
    "sha256",
    "sha512",
    "to_base32",
    "to_base64",
    "to_hex",
    "url_decode",
    "url_encode",
    "using_policy",
    "xor",
]
