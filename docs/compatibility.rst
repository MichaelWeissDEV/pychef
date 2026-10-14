Compatibility and current status
================================

Pinned reference
----------------

The operation inventory is pinned to CyberChef 11.3.0 at commit
``c56dd23358e948aff9f3f98913818e544227da13``.

* Upstream operation names in the pinned inventory: 502
* Registered PyChef operation names: 502
* Missing names: 0
* Name coverage: 100%

Every registered name has a dedicated Python module and an individual page in
the :doc:`operations/index`. The documentation generator verifies that current
registry names have matching pinned metadata.

What “implemented” means
------------------------

“Implemented” means an operation is registered and callable. It does **not**
mean that every combination of every option is already byte-for-byte identical
to upstream CyberChef. Option-level confidence comes from tests ported to pytest
and independent format or algorithm vectors.

Each operation page therefore shows:

* whether the operation is registered;
* positional options and defaults discovered from the Python implementation;
* upstream option labels and choices from the pinned source;
* a call example or explicit template;
* known broad limitations where applicable.

Known broad boundaries
----------------------

The most important remaining parity boundaries include arbitrary QR-symbol
decoding; palette/interlaced PNG, progressive/CMYK JPEG, and compressed TIFF;
complete Typex/SIGABA/Lorenz presets; full JavaScript, jq, Jsonata, and YARA
grammars; general-purpose OCR; complete instruction decoding; AMF3
externalizable values; and interoperable OpenPGP packets.

These boundaries do not mean every input to the named operation fails. They mean
the current pure-Python implementation supports a documented subset and should
be verified with representative data before production use.

Inspect status from Python
--------------------------

.. code-block:: python

   from pychef import compatibility_report

   report = compatibility_report()
   print(report.upstream_version)
   print(len(report.implemented))
   print(report.missing)
   print(report.complete)

The repository also keeps the exhaustive name matrix in ``COMPATIBILITY.md``.
When updating the pinned upstream release, regenerate metadata, port or add
vectors, and update the compatibility notes in the same change.

Differences from CyberChef
--------------------------

* PyChef is a Python library. It has no graphical interface, no web server, and
  no JavaScript runtime.
* Safe default limits apply to every execution (:doc:`errors-and-safety`);
  CyberChef itself has no such limits. Use ``ExecutionPolicy.unrestricted()`` to
  lift them.
* Network operations are off unless a policy grants them.
* ``str`` and ``bytes`` are distinct; CyberChef's ``ArrayBuffer`` and string
  types map to ``bytes`` and ``str`` as described in :doc:`data-model`.
* The ``pychef.ops`` helpers use Python-friendly defaults in one place: ``to_hex``
  defaults to no delimiter (the recipe default is ``"Space"``), matching
  ``Pipeline.to_hex``.
