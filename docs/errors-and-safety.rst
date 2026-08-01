Errors, safety, and performance
===============================

Error classes
-------------

All library-specific exceptions derive from :class:`pychef.PyChefError`.

* :class:`pychef.RecipeError` reports invalid recipe or pipeline-to-recipe conversion.
* :class:`pychef.UnknownOperationError` reports an exact name that is not registered.
* :class:`pychef.OperationError` wraps an exception raised while a recipe operation runs
  and retains the operation name.

Helpers such as ``pack``, ``decode_bytes``, and packet parsers use normal
``ValueError`` or ``TypeError`` for invalid direct arguments.

.. code-block:: python

   from pychef import OperationError, bake

   try:
       bake("invalid", ["From Hex"])
   except OperationError as error:
       print(error.operation, error)

Network access
--------------

Importing PyChef performs no network requests. Only explicitly executing
network-capable operations such as ``HTTP request`` and ``DNS over HTTPS`` may
access a network. Their implementation rejects credentials in URLs and
local/private/reserved destinations. Treat remote responses as untrusted input.

Cryptography
------------

PyChef's algorithms are intended for compatibility, education, tests, and CTF
workflows. Pure-Python implementations are not a substitute for a professionally
audited cryptographic library when protecting real keys or building a production
security protocol. Never reuse a nonce or IV where the chosen mode forbids it.

Untrusted and large inputs
--------------------------

Binary parsers validate sizes and offsets, and capture readers expose resource
limits. A recipe can still be computationally expensive by design: compression,
password hashing, regular expressions, images, OCR, and deliberate ``Sleep`` or
flow-control loops deserve application-level time and memory budgets.

Performance
-----------

Construct :class:`pychef.Recipe` or :class:`pychef.Pipeline` once and reuse it.
This avoids repeated configuration parsing. Keep values as bytes during binary
work and decode only at a known text boundary. ``transform_many`` retains order
but intentionally runs synchronously; use application-level worker processes for
CPU-heavy independent inputs when appropriate.
