Direct operations
=================

``pychef.ops`` provides plain functions for common transformations. They need no
recipe list and no pipeline object:

.. doctest::

   >>> from pychef.ops import from_hex, to_base64, sha256
   >>> data = from_hex("414243")
   >>> data
   b'ABC'
   >>> to_base64(data)
   'QUJD'
   >>> sha256(data)[:16]
   'b5d4045c3f466fa9'

Each function runs the registered CyberChef operation through the regular engine,
so results match ``bake`` and ``Pipeline``. Options are keyword-only and named;
unknown values are rejected by the operation.

Types
-----

* Input: ``str`` (UTF-8 encoded when bytes are needed) or bytes-like
  (``bytes``, ``bytearray``, ``memoryview``). Anything else raises ``TypeError``.
* Decoders (``from_*``, ``xor``, ``gzip_*``) return ``bytes``.
* Encoders (``to_*``, ``url_*``, ``html_*``) and hashes return ``str``.
* ``rot13`` and ``reverse`` return the type they were given: ``str`` for ``str``,
  ``bytes`` for bytes-like.

Policy
------

Calls use ``ExecutionPolicy.safe()`` unless you choose otherwise. Resolution order:
an explicit ``policy=`` (``run_operation`` only), then the **innermost** active
policy -- a :func:`~pychef.ops.using_policy` block or a running ``bake``/``Pipeline``/``Chef``
execution (for example inside a ``Pipeline.apply`` callable), whichever was entered
last -- then the safe default.

.. doctest::

   >>> from pychef import ExecutionLimitError, ExecutionPolicy
   >>> from pychef.ops import to_hex, using_policy
   >>> with using_policy(ExecutionPolicy(max_input_bytes=2)):
   ...     try:
   ...         to_hex(b"abc")
   ...     except ExecutionLimitError as error:
   ...         print(error.limit)
   max_input_bytes

Network operations are denied under the default policy, exactly as in ``bake``.

Function reference
------------------

.. list-table::
   :header-rows: 1

   * - Function
     - Returns
     - CyberChef operation
     - Notes
   * - ``from_hex(value, *, delimiter="Auto")``
     - ``bytes``
     - From Hex
     -
   * - ``to_hex(value, *, delimiter="None", bytes_per_line=0)``
     - ``str``
     - To Hex
     - Default delimiter ``"None"`` (the recipe default is ``"Space"``); same as ``Pipeline.to_hex``
   * - ``from_base64(value, *, alphabet=..., remove_non_alphabet=True, strict=False)``
     - ``bytes``
     - From Base64
     -
   * - ``to_base64(value, *, alphabet=...)``
     - ``str``
     - To Base64
     -
   * - ``from_base32`` / ``to_base32``
     - ``bytes`` / ``str``
     - From Base32 / To Base32
     -
   * - ``url_encode(value, *, encode_all=False)``
     - ``str``
     - URL Encode
     -
   * - ``url_decode(value, *, plus_as_space=True)``
     - ``str``
     - URL Decode
     -
   * - ``html_encode(value, *, convert_all=False, format=...)``
     - ``str``
     - To HTML Entity
     -
   * - ``html_decode(value)``
     - ``str``
     - From HTML Entity
     -
   * - ``rot13(value, *, amount=13, lowercase=True, uppercase=True, numbers=False)``
     - ``str`` or ``bytes``
     - ROT13
     - Result type follows input type
   * - ``reverse(value, *, by=...)``
     - ``str`` or ``bytes``
     - Reverse
     - Text defaults to ``"Character"``, bytes to ``"Byte"``
   * - ``xor(value, key, *, key_format="raw", scheme="Standard", null_preserving=False)``
     - ``bytes``
     - XOR
     - Empty keys are rejected
   * - ``gzip_compress`` / ``gzip_decompress``
     - ``bytes``
     - Gzip / Gunzip
     -
   * - ``md5``, ``sha1``, ``sha256``, ``sha512``, ``digest``
     - ``str`` (``bytes`` for ``output="raw"``)
     - (uses ``hashlib``)
     - Same functions and format as :mod:`pychef.ctf`

Errors
------

Invalid input types raise ``TypeError``. Bad option values raise ``ValueError`` or
an ``OperationError`` from the underlying operation; limit and permission problems
raise ``ExecutionLimitError`` and ``OperationPermissionError``.

Any other operation
-------------------

.. doctest::

   >>> from pychef.ops import run_operation
   >>> run_operation("To Hex", b"AB", args=("Colon", 0))
   '41:42'

``value`` is the input, ``args`` the positional operation arguments, and
``policy`` the engine policy. The three never overlap. The result is ``str`` or
``bytes`` depending on the operation.
