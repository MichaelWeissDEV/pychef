Recipes, pipelines, or direct operations
========================================

PyChef has four entry points on one shared engine. They differ in ergonomics, not
in behavior: the same operation produces the same result and is bound by the same
:class:`~pychef.ExecutionPolicy` whichever you use.

.. list-table::
   :header-rows: 1
   :widths: 18 30 26 26

   * - Entry point
     - Best for
     - Strengths
     - Limits
   * - ``pychef.ops`` functions
     - One or two transformations inside normal code
     - Named options, precise return types, IDE completion
     - Curated set; use ``run_operation`` for the rest
   * - ``bake`` / ``Recipe``
     - CyberChef recipes, JSON-stored configuration, all 502 operations
     - Data-driven, serializable, flow control (Fork, Jump, ...)
     - Positional arguments, loosely typed results
   * - ``Pipeline``
     - Reusable multi-step transformations mixed with Python code
     - Immutable, composable, traceable, streaming and batching
     - Python stages are trusted code, not sandboxed
   * - ``Chef`` / ``IsolatedWorker``
     - Repeated runs with one policy, registry, or process isolation
     - Central configuration, diagnostics (``bake_result``), hard deadlines
     - Subprocess overhead when isolated

The same task, three ways
-------------------------

.. doctest::

   >>> from pychef import Pipeline, bake
   >>> from pychef.ops import from_hex, to_base64
   >>> bake("414243", ["From Hex", "To Base64"])
   'QUJD'
   >>> Pipeline().from_hex().to_base64()("414243")
   'QUJD'
   >>> to_base64(from_hex("414243"))
   'QUJD'

Rules of thumb
--------------

* One step, no configuration: use ``pychef.ops``.
* A transformation you reuse or combine with your own functions: use ``Pipeline``.
* A recipe you received as data, or an operation without a helper: use ``bake``
  or ``ops.run_operation``.
* A service that executes many untrusted recipes: use ``Chef`` with
  ``ExecutionPolicy.untrusted()`` and, for hard limits, ``IsolatedWorker``.

Security does not depend on the entry point
-------------------------------------------

``pychef.ops``, ``bake``, ``Pipeline`` and ``Chef`` all default to
``ExecutionPolicy.safe()``: bounded input, output, steps, and time, and no network.
The functions under ``pychef.operations.by_operation`` are internal
implementations: they perform no input/output/step limiting, and the HTTP
operations fall back to ``NetworkPolicy.public_only()`` (network *allowed*) when
called outside any execution. Do not call them directly with untrusted input.
