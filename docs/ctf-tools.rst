CTF and binary tools
====================

PyChef exposes Python-native helpers for common exploit-development, reversing,
forensics, and CTF tasks. They operate directly on bytes and integers and can be
used independently of recipes.

Packing and endianness
----------------------

The short names follow familiar CTF conventions. ``p*`` packs an integer;
``u*`` unpacks bytes. The unsuffixed 16/32/64-bit forms default to little endian.

.. code-block:: python

   from pychef import p16be, p32, p64le, u16be, u32

   assert p32(0x12345678) == b"\x78\x56\x34\x12"
   assert p16be(0x1234) == b"\x12\x34"
   assert p64le(1) == b"\x01\x00\x00\x00\x00\x00\x00\x00"
   assert u32(b"\x78\x56\x34\x12") == 0x12345678
   assert u16be(b"\x12\x34") == 0x1234

``pack`` and ``unpack`` support any positive byte-aligned width, signed values,
explicit byte order, and an unpack offset.

.. code-block:: python

   from pychef import pack, unpack

   encoded = pack(-2, 24, endian="big", signed=True)
   assert unpack(encoded, 24, endian="big", signed=True) == -2

Use ``swap_endian(data, word_size=4)`` to reverse bytes inside each word rather
than reversing the entire buffer.

Payload construction
--------------------

``flat`` combines integers, text, bytes, and nested sequences. Integers use the
selected word width and endian order.

.. code-block:: python

   from pychef import flat

   payload = flat(b"HEAD", 0xDEADBEEF, [b"A", b"B"], word_size=32)

``chunks`` splits text or bytes while retaining the input type. ``hexdump``
creates a readable address/hex/ASCII display.

Cyclic patterns
---------------

.. code-block:: python

   from pychef import cyclic, cyclic_find

   pattern = cyclic(256)
   crashed_value = pattern[72:76]
   assert cyclic_find(crashed_value) == 72

XOR and rotations
-----------------

.. code-block:: python

   from pychef import rol, ror, xor_bytes

   assert xor_bytes(b"ABC", b"\x01") == b"@CB"
   assert ror(rol(0xDEADBEEF, 7), 7) == 0xDEADBEEF

Hashing
-------

``digest`` accepts algorithms exposed by Python's ``hashlib`` and returns hex by
default. Output can be ``hex``, ``base64``, or raw ``bytes``. Convenience helpers
include ``md5``, ``sha1``, ``sha256``, ``sha512``, and ``digests``.

.. code-block:: python

   from pychef import digest, sha256

   assert sha256(b"hello") == digest(b"hello", algorithm="sha256")
   raw = digest(b"hello", algorithm="sha256", output="raw")

AES
---

``aes_encrypt`` and ``aes_decrypt`` support ECB, CBC, CFB, OFB, CTR, and GCM.
ECB does not use an IV. Other modes require an explicit IV or nonce. Block-mode
padding can be ``pkcs7`` or ``none``. GCM authenticates optional AAD
and appends a 16-byte tag by default.

.. code-block:: python

   from pychef import aes_decrypt, aes_encrypt

   key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
   iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
   ciphertext = aes_encrypt(b"attack at dawn", key, mode="CBC", iv=iv)
   assert aes_decrypt(ciphertext, key, mode="CBC", iv=iv) == b"attack at dawn"

Use ``aes_gcm_encrypt`` and ``aes_gcm_decrypt`` for detached GCM tags. Textual
keys, IVs, and tags must declare formats such as ``key_format="hex"``. Do not use
pure-Python compatibility cryptography as a substitute for an audited security
library in production key-management or protocol implementations.
