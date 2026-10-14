Pipelines
=========

:class:`pychef.Pipeline` builds an immutable chain that can mix registered
operations, Python callables, branches, CTF helpers, and packet parsers.

Add operations
--------------

``then`` accepts the exact operation name followed by positional arguments:

.. code-block:: python

   from pychef import Pipeline

   transform = (
       Pipeline()
       .then("From Hex", "Auto")
       .then("XOR", {"option": "Hex", "string": "42"}, "Standard", False)
       .then("Decode text", "UTF-8 (65001)")
   )

   assert transform("0a272e2e2d") == "Hello"

``operation`` is an alias for ``then``. Common operations have readable helpers
such as ``from_hex``, ``to_hex``, ``from_base64``, ``to_base64``, ``decode``, and
``encode``.

Reuse and batch processing
--------------------------

Each chain call returns a new object. The base pipeline remains reusable:

.. code-block:: python

   base = Pipeline().from_hex()
   as_text = base.decode()
   as_base64 = base.to_base64()

   values = as_text.transform_many(["41", "42", "43"])
   assert values == ("A", "B", "C")

Call ``pipeline(value)``, ``pipeline.transform(value)``, ``pipeline.run(value)``,
or ``pipeline.bake(value)``; all four execute the same chain.

Compose pipelines
-----------------

``|`` joins two pipelines. A value on the left executes a pipeline:

.. code-block:: python

   decode = Pipeline().from_base64().decode()
   normalize = Pipeline().apply(str.strip).apply(str.lower)
   combined = decode | normalize

   assert combined("IEhlbGxvICAK") == "hello"
   assert "IEhlbGxvICAK" | combined == "hello"

Append Python logic
-------------------

``apply`` adds any one-argument callable. Give lambdas a name to make traces easy
to understand:

.. code-block:: python

   length = Pipeline().from_hex().apply(len, name="byte length")
   assert length("00010203") == 4

The callable receives exactly the previous stage's output. Exceptions are not
silently swallowed.

Branches and concatenation
--------------------------

``concat`` runs every branch with the same current value, then joins its outputs.
All branches must return ``str`` for a string separator or ``bytes`` for a bytes
separator.

.. code-block:: python

   hashes = Pipeline().concat(
       Pipeline().digest("md5"),
       Pipeline().digest("sha256"),
       separator=":",
   )

   line = hashes(b"flag")
   md5_value, sha256_value = line.split(":")

``append`` and ``prepend`` are convenience branches for constants:

.. code-block:: python

   frame = Pipeline().prepend(b"BEGIN:").append(b":END")
   assert frame(b"data") == b"BEGIN:data:END"

Select structured output
------------------------

``select`` walks dictionary keys, sequence indexes, or attributes:

.. code-block:: python

   source = Pipeline().parse_capture().select(
       "packets", 0, "decoded", "network", "source"
   )
   address = source(pcap_bytes)

Trace intermediate results
--------------------------

``trace`` returns one :class:`pychef.PipelineTrace` per stage:

.. code-block:: python

   pipeline = Pipeline().from_hex().xor(b"\x42").decode()
   for stage in pipeline.trace("0a272e2e2d"):
       print(stage.name, repr(stage.input), "->", repr(stage.output))

Typed CTF and packet stages
---------------------------

The pipeline API includes ``digest``, ``xor``, ``swap_endian``, ``pack``,
``unpack``, ``hexdump``, ``aes_encrypt``, ``aes_decrypt``, ``parse_packet``, and
``parse_capture``. These are Python-native stages, so their keyword arguments are
type-checker friendly. For example:

.. code-block:: python

   decrypt = Pipeline().aes_decrypt(
       "00112233445566778899aabbccddeeff",
       mode="CBC",
       iv="000102030405060708090a0b0c0d0e0f",
       key_format="hex",
       iv_format="hex",
   )

Use a named helper when it exists; use ``then`` for any of the 502 registered
operations. The individual operation pages show the correct positional order.

Execution budgets, branches, and trusted callables
--------------------------------------------------

One call, one context
~~~~~~~~~~~~~~~~~~~~~

A single ``pipeline(value, policy=...)`` call creates exactly one execution
context. Steps, branches, output limits, the deadline, and the network policy are
accounted for the **whole call, including every branch created with** ``concat``
(and nested ``concat`` branches). A branch can never reset a budget or fall back to
the safe defaults, and an explicitly ``unrestricted`` policy stays unrestricted
inside branches. Branch steps appear in traces with their ``branch_path``.

.. code-block:: python

   pipeline = Pipeline().concat(Pipeline().from_hex(), Pipeline().from_hex())
   pipeline("4142", policy=ExecutionPolicy(max_steps=3))   # concat + 2 branch steps: OK
   pipeline("4142", policy=ExecutionPolicy(max_steps=2))   # raises ExecutionLimitError

Batches and streams
~~~~~~~~~~~~~~~~~~~

``transform_many(values)`` consumes a finite iterable and returns a **tuple**
(materialized, order preserved). ``iter_transform(values)`` is a generator: it
pulls one item at a time and yields each result immediately, so large inputs do not
have to fit in memory. Both share one execution context across all items, which
means **one step budget and one deadline for the entire batch or stream**. Under the
default ``ExecutionPolicy.safe()`` a stream therefore ends with
``ExecutionLimitError`` after 10,000 total steps, or with ``ExecutionTimeoutError``
30 seconds after the first item is requested; that wall-clock time includes the time
your code spends between ``next()`` calls. For long-running or effectively unbounded
streams pass an explicit policy, for example
``ExecutionPolicy(max_steps=None, cooperative_deadline_seconds=None)``. An exception in one item propagates and ends the iteration;
call ``pipeline(item)`` per item (each call has its own context) for independent
budgets or per-item error handling.

Trusted callables only
~~~~~~~~~~~~~~~~~~~~~~

``apply`` runs arbitrary Python code that you supply. It is a feature for
trusted code, **not a sandbox**: PyChef cannot constrain what a callable does,
resource checks inside it are not guaranteed (limits are enforced between stages),
and it has the permissions of your process. Never build a pipeline from callables
supplied by untrusted parties. For untrusted *recipes* (data), use
``ExecutionPolicy.untrusted()`` and :class:`pychef.IsolatedWorker`; see
:doc:`errors-and-safety`.

Pipeline helpers inherit nothing from your callable: a ``pychef.ops`` function
called inside an ``apply`` stage uses the policy of the running pipeline.
