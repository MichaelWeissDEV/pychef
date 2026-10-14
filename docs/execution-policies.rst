Execution policies
==================

An :class:`~pychef.ExecutionPolicy` is the set of limits and permissions the *host*
grants to an execution. This page is the practical guide; :doc:`errors-and-safety`
explains the security model.

Profiles
--------

.. doctest::

   >>> from pychef import ExecutionPolicy
   >>> safe = ExecutionPolicy.safe()
   >>> safe.max_input_bytes, safe.max_steps, safe.allow_network
   (16777216, 10000, False)
   >>> ExecutionPolicy.unrestricted().max_steps is None
   True

Custom limits
-------------

Every limit can be set, or disabled explicitly with ``None``:

.. doctest::

   >>> from pychef import ExecutionLimitError, Pipeline
   >>> policy = ExecutionPolicy(
   ...     max_input_bytes=16 * 1024 * 1024,
   ...     max_output_bytes=64 * 1024 * 1024,
   ...     max_steps=10_000,
   ...     cooperative_deadline_seconds=30.0,
   ... )
   >>> Pipeline().from_hex()("414243", policy=policy)
   b'ABC'
   >>> try:
   ...     Pipeline().from_hex()("4142", policy=ExecutionPolicy(max_steps=0))
   ... except ExecutionLimitError as error:
   ...     print(error.limit)
   max_steps
   >>> ExecutionPolicy(max_steps=None).max_steps is None
   True

``with_overrides`` derives a variant of an existing policy.

Cooperative limits versus process isolation
-------------------------------------------

Limits are checked **between steps** in the calling process (cooperative). They
cannot interrupt a single long-running step or a Python callable. For untrusted
recipes use :doc:`worker isolation <errors-and-safety>` (``IsolatedWorker``): the
deadline is enforced from outside, and on Linux a hard OS memory limit is available.

Budgets and nesting
-------------------

One execution has one :class:`~pychef.ExecutionContext` holding the consumed budget
(steps, branches, depth, deadline, trace). A nested call -- ``bake``, ``Pipeline`` or
``pychef.ops`` invoked from a ``Pipeline.apply`` callable -- shares it and cannot
reset it; a different policy inside a running execution raises ``ValueError``. See
:doc:`direct-operations` for the full rules.

Network
-------

Network access is denied unless the policy's :class:`~pychef.NetworkPolicy` allows
it. See the network section of :doc:`errors-and-safety`.
