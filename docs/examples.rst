Practical examples
==================

Decode an unknown hexadecimal text
----------------------------------

.. code-block:: python

   from pychef import Pipeline

   decode = Pipeline().from_hex().decode()
   print(decode("666c61677b7079636865667d"))
   # flag{pychef}

Create a reusable file fingerprint function
-------------------------------------------

.. code-block:: python

   from pathlib import Path

   from pychef import Pipeline

   sha256_hex = Pipeline().digest("sha256")
   fingerprint = sha256_hex(Path("sample.bin").read_bytes())
   print(fingerprint)

Try several decoders without rebuilding them
---------------------------------------------

.. code-block:: python

   from pychef import Pipeline

   candidates = {
       "hex": Pipeline().from_hex(),
       "base64": Pipeline().from_base64(),
       "url": Pipeline().then("URL Decode"),
   }

   for label, decoder in candidates.items():
       try:
           print(label, decoder(encoded_value))
       except Exception as error:
           print(label, "failed:", error)

Build a binary payload
----------------------

.. code-block:: python

   from pychef import cyclic, flat, p32, p64

   payload = flat(
       cyclic(40),
       p32(0xDEADBEEF),
       p64(0x40123A),
       b"/bin/sh\x00",
   )

Inspect a packet capture
------------------------

.. code-block:: python

   from pychef import read_capture

   capture = read_capture("challenge.pcap")
   for packet in capture["packets"]:
       decoded = packet.get("decoded", {})
       network = decoded.get("network", {})
       transport = network.get("transport", {})
       print(
           network.get("source"),
           "->",
           network.get("destination"),
           transport.get("destination_port"),
       )

AES-GCM with associated data
----------------------------

.. code-block:: python

   from pychef import aes_gcm_decrypt, aes_gcm_encrypt

   key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
   nonce = bytes.fromhex("101112131415161718191a1b")
   ciphertext, tag = aes_gcm_encrypt(b"secret", key, iv=nonce, aad=b"header")
   plaintext = aes_gcm_decrypt(ciphertext, key, iv=nonce, tag=tag, aad=b"header")

   assert plaintext == b"secret"
