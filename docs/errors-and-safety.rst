Errors, safety, and performance
===============================

Execution policies and safety profiles
---------------------------------------

PyChef operates under a **safe-by-default, configurable-by-design** security philosophy.
Unrestricted execution is always available when explicitly chosen by the caller,
while untrusted input is protected from unbounded memory consumption, runaway CPU
loops, and unexpected network access.

PyChef provides pre-defined profiles via :class:`pychef.ExecutionPolicy`:

* ``ExecutionPolicy.safe()`` (Default): Conservative resource limits (512 MiB memory,
  16 MiB input, 64 MiB output, 10,000 steps/branches, 30s cooperative deadline) and
  network access completely disabled.
* ``ExecutionPolicy.untrusted()``: Stricter sandboxing (64 MiB memory, 4 MiB input,
  8 MiB output, 1,000 steps/branches, 5s deadline, disabled network).
* ``ExecutionPolicy.unrestricted()``: Lifts all internal resource caps (sets limits to
  ``None``) and permits unrestricted network connections.
* ``ExecutionPolicy.permissive()``: Backward-compatibility profile with unlimited
  budgets and standard public network access.

An explicit ``None`` passed for any numeric budget completely disables that limit:

.. code-block:: python

   from pychef import ExecutionPolicy, bake

   # Completely uncapped memory and steps, but keep 10-second timeout
   policy = ExecutionPolicy(
       max_memory_bytes=None,
       max_steps=None,
       cooperative_deadline_seconds=10.0,
   )
   bake(large_data, ["To Hex"], policy=policy)

Network security and permissions
--------------------------------

Outbound network operations (``HTTP request``, ``DNS over HTTPS``) are governed by
:class:`pychef.NetworkPolicy`:

* **Modes**: ``"disabled"`` (default in safe profile), ``"public_only"`` (blocks private/loopback/link-local/metadata IPs),
  or ``"unrestricted"`` (allows connecting to private services and localhost for security audits/CTFs).
* **SSRF Protection & DNS Pinning**: Every outbound connection validates IP addresses against policy
  rules and connects directly to the validated IP to prevent DNS rebinding attacks. Environment proxies
  (``HTTP_PROXY``) are bypassed to enforce destination controls.
* **Allow- and Deny-Lists**: Hostnames (``allowed_hosts``, ``denied_hosts``), subnets (``allowed_subnets``,
  ``denied_subnets``), ports (``allowed_ports``, ``denied_ports``), and schemes (``allowed_schemes``).

.. code-block:: python

   from pychef import ExecutionPolicy, NetworkPolicy, bake

   # Permit public requests plus specific internal telemetry host
   net_policy = NetworkPolicy(
       mode="public_only",
       allowed_hosts=("internal-api.corp.local",),
       allowed_subnets=("10.20.0.0/16",),
   )
   policy = ExecutionPolicy.safe(network=net_policy)
   bake("", [{"op": "HTTP request", "args": ["GET", "https://internal-api.corp.local/data"]}], policy=policy)

Worker isolation
----------------

For maximum defence-in-depth against catastrophic regular expression backtracking,
C-extension crashes, or memory exhaustion, PyChef provides process-isolated execution
via :class:`pychef.IsolatedWorker` and ``bake_isolated``:

.. code-block:: python

   from pychef import bake_isolated, ExecutionPolicy

   # Run recipe in dedicated child process with hard OS limit and deadline
   result = bake_isolated(
       untrusted_payload,
       [{"op": "Regular expression", "args": ["User Regex", "$1", True, True, False, False, False, False, "Highlight matches"]}],
       policy=ExecutionPolicy.safe(),
       timeout=2.0,
   )

Alternatively, pass ``isolated=True`` directly to :func:`pychef.bake`:

.. code-block:: python

   from pychef import bake

   result = bake(data, recipe, isolated=True)

Structured errors
-----------------

All library exceptions inherit from :class:`pychef.PyChefError` and provide rich,
machine-readable metadata for debugging and logging:

* ``error_code``: Machine-readable identifier (e.g. ``"limit_exceeded"``, ``"permission_denied"``, ``"operation_failed"``).
* ``operation_name``: Name of the active operation when the failure occurred.
* ``step_index``: Zero-based index of the failing step in the recipe/pipeline.
* ``branch_path``: Hierarchical path inside nested forks or subsections (e.g. ``(0, 3)``).
* ``execution_id``: Unique identifier correlating operations within a single execution.
* ``to_dict()``: Serializes error metadata for structured JSON logging.

Hierarchy:

* :class:`pychef.ExecutionLimitError`: Exceeded cooperative memory, step, branch, recursion, or output limits.
* :class:`pychef.ExecutionTimeoutError`: Exceeded cooperative deadline or worker hard timeout.
* :class:`pychef.OperationPermissionError`: Attempted an operation forbidden by policy (such as network access when disabled).
* :class:`pychef.InvalidOperationArgumentsError`: Malformed operation arguments or regular expressions.
* :class:`pychef.UnknownOperationError`: Reference to an unregistered operation name.
* :class:`pychef.OperationError`: Transformation failure inside an operation.
* :class:`pychef.RecipeError`: Malformed recipe structure.

Streaming pipelines
-------------------

:class:`pychef.Pipeline` supports memory-efficient streaming across large sequences of items:

.. code-block:: python

   from pychef import Pipeline

   pipeline = Pipeline().apply(str.strip).then("To Base64")

   # Streams elements one at a time with a shared execution budget
   for transformed in pipeline.iter_transform(large_stream):
       process(transformed)

Metadata and introspection
--------------------------

PyChef operations are completely catalogued and inspectable at runtime via :func:`pychef.get_operation_spec`:

.. code-block:: python

   import pychef

   spec = pychef.get_operation_spec("AES Decrypt")
   print(spec.name, spec.category, spec.description)
   for arg in spec.arguments:
       print(f"Arg: {arg.name} (type: {arg.type}, default: {arg.default})")

Policy, context, and the host/recipe boundary
---------------------------------------------

An :class:`~pychef.ExecutionPolicy` says what is allowed (limits, network). An
:class:`~pychef.ExecutionContext` is the state of one running execution (steps used,
branches, depth, deadline, trace, execution id). One execution has one context, no
matter whether it runs through ``bake``, ``Chef``, ``Pipeline`` or ``pychef.ops``;
nested calls inherit it and cannot reset it (details in :doc:`direct-operations`).

The policy is chosen by the **host** -- the code that starts the execution. Settings
inside a recipe, and nested calls, cannot replace it: supplying a different policy
inside a running execution raises ``ValueError`` instead of widening permissions.
Host-written Python callables (``Pipeline.apply``) are trusted and may do anything the
host process can; the policy governs registered operations, not arbitrary Python.
Disabling an optional limit with ``None`` is a deliberate host decision and stays
disabled for nested calls; it does not authorize anything beyond the policy itself.

``IsolatedWorker`` deadlines
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The worker deadline covers receiving the whole result message, including a message
the child stalls in the middle of. At the deadline the child is terminated (up to
about two seconds of grace before it is killed) and the reader thread is joined for
at most one more second. Total overshoot is therefore bounded by roughly three
seconds. If a *descendant* of the child kept the pipe open, the blocked reader thread
cannot be interrupted portably; it is parked as a daemon thread and its connection is
left open until the handle is released. Without a deadline (``timeout=None`` and
``cooperative_deadline_seconds=None``) the parent waits indefinitely for the child.
