Text, bytes, and structured data
================================

Understanding the value passed between steps prevents most beginner mistakes.

``str`` and ``bytes``
---------------------

Recipes start with either Python ``str`` or ``bytes``. Every operation receives
the previous operation's output. Encoders and binary decoders commonly return
``bytes``; text-formatting operations commonly return ``str``. PyChef does not
silently convert every intermediate result because doing so could corrupt binary
data.

.. code-block:: python

   from pychef import bake

   raw = bake("414243", [{"op": "From Hex", "args": ["Auto"]}])
   assert raw == b"ABC"

   text = bake(
       "414243",
       [
           {"op": "From Hex", "args": ["Auto"]},
           {"op": "Decode text", "args": ["UTF-8 (65001)"]},
       ],
   )
   assert text == "ABC"

Use ``return_type`` when only the final value needs conversion:

.. code-block:: python

   from pychef import bake

   assert bake("4142", ["From Hex"], return_type="str") == "AB"
   assert bake("hello", [], return_type="bytes") == b"hello"

Explicit byte formats
---------------------

CTF helpers accept explicit formats instead of guessing:

.. code-block:: python

   from pychef import decode_bytes, encode_bytes

   key = decode_bytes("001122ff", format="hex")
   printable = encode_bytes(key, format="base64")

Supported formats are ``raw``, ``utf8``, ``hex``, ``base64``, and ``latin1``.
For cryptographic keys and IVs, prefer bytes or set ``key_format`` and
``iv_format`` explicitly.

Structured pipeline values
--------------------------

Registered CyberChef operations accept text or bytes. Python callable stages and
packet parsers may additionally produce dictionaries, lists, integers, or custom
objects. Use :meth:`pychef.Pipeline.select` to select a nested value before the next
stage:

.. code-block:: python

   from pychef import Pipeline

   get_name = (
       Pipeline()
       .apply(lambda value: {"user": {"name": value.strip()}})
       .select("user", "name")
   )

   assert get_name(" Alice ") == "Alice"

Recipe arguments
----------------

Operation arguments can be strings, numbers, booleans, lists, or dictionaries.
Their positions matter. Copy the order shown on the operation's reference page.
An omitted argument uses that Python implementation's default; an explicitly
passed empty string is still an argument and can mean something different.
