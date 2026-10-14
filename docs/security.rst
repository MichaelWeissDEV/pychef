Security considerations
=======================

What PyChef protects against
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Unbounded memory, output, steps, branches, recursion, and time in registered
  operations (cooperative, see :doc:`execution-policies`).
* Unintended network access: denied by default; when allowed, SSRF checks, DNS
  pinning, per-hop redirect validation, and credential stripping across origins.
* Leakage of keys and inputs through error messages (secret redaction).

What it does not protect against
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Arbitrary Python you supply (``Pipeline.apply``, custom registry functions) -- trusted
  code only.
* A single step that runs for a very long time inside the same process; use
  ``IsolatedWorker`` for untrusted recipes. Hard memory limits exist on Linux only.
* Cryptographic misuse: several legacy algorithms are included for compatibility with
  CyberChef and are not recommended for new designs. The implementations are pure
  Python and not hardened against timing side channels.
* Exact parity with every CyberChef option -- see :doc:`compatibility`.

Host versus recipe
~~~~~~~~~~~~~~~~~~

The host picks the ``ExecutionPolicy``. Recipes, nested calls, and ``using_policy`` inside
a running execution cannot widen it. Details: :doc:`errors-and-safety`.

Reporting vulnerabilities: see ``SECURITY.md`` in the repository.
