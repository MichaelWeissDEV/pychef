Cookbook
========

Short, tested recipes. Runnable scripts live in the repository's ``examples/``
directory.

Encoding and decoding
---------------------

.. doctest::

   >>> from pychef.ops import from_base64, html_decode, html_encode, url_decode, url_encode
   >>> from_base64("SGVsbG8=")
   b'Hello'
   >>> url_encode("a b&c")
   'a%20b%26c'
   >>> url_decode("a%20b%26c")
   'a b&c'
   >>> html_decode(html_encode("<b>"))
   '<b>'

Hashing
-------

.. doctest::

   >>> from pychef.ops import digest, md5
   >>> md5("hello")
   '5d41402abc4b2a76b9719d911017c592'
   >>> digest(b"hello", algorithm="sha1", output="base64")
   'qvTGHdzF6KLavt4PO0gs2a6pQ00='

Binary processing
-----------------

.. doctest::

   >>> from pychef import p32le, u32le, xor_bytes
   >>> packed = p32le(0xDEADBEEF)
   >>> packed.hex()
   'efbeadde'
   >>> u32le(packed) == 0xDEADBEEF
   True
   >>> xor_bytes(b"\x00\xff", b"\xff")
   b'\xff\x00'

CTF workflows
-------------

Multi-stage decoding is a short pipeline:

.. doctest::

   >>> from pychef import Pipeline
   >>> solve = Pipeline().from_base64().from_hex().xor(b"\x01").decode()
   >>> solve("NDk0NDQ1NDg=")
   'HEDI'

Network data
------------

.. doctest::

   >>> from pychef import parse_ipv4_packet
   >>> packet = bytes.fromhex("4500001c0001000040110000c0a80001c0a800020035003500080000")
   >>> parse_ipv4_packet(packet)["destination"]
   '192.168.0.2'

File processing
---------------

Read bytes, transform, write with an explicit encoding; see
``examples/file_encoding.py``. For multi-megabyte files prefer chunked processing
with :meth:`pychef.Pipeline.iter_transform`.
