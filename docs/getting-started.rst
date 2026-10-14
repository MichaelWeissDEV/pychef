Getting started
===============

PyChef is an unofficial, pure-Python library for CyberChef-style data
transformations. This page takes you from installation to a first transformation
with each of its four entry points.

Requirements
------------

Python 3.10 or newer on Linux, macOS, or Windows. There are no runtime
dependencies.

Install
-------

The distribution and the import name are intentionally different:

.. list-table::
   :header-rows: 1

   * - What
     - Name
   * - Install (PyPI distribution)
     - ``cyberchef-py``
   * - Import (Python package)
     - ``pychef``

.. code-block:: console

   $ python -m pip install cyberchef-py

or with uv:

.. code-block:: console

   $ uv add cyberchef-py

.. doctest::

   >>> import pychef
   >>> isinstance(pychef.__version__, str)
   True
   >>> len(pychef.list_operations())
   502

First transformation
--------------------

The same transformation, four ways. All of them run the same engine and apply the
same default safety limits (see :doc:`errors-and-safety`).

**1. A direct operation** (:doc:`direct-operations`) is the shortest path for a
single step:

.. doctest::

   >>> from pychef.ops import from_hex, to_base64
   >>> to_base64(from_hex("414243"))
   'QUJD'

**2. A recipe** is a list of CyberChef-compatible steps (:doc:`recipes`):

.. doctest::

   >>> from pychef import bake
   >>> bake("414243", ["From Hex", "To Base64"])
   'QUJD'

**3. A pipeline** is a reusable, immutable chain with readable methods
(:doc:`pipelines`):

.. doctest::

   >>> from pychef import Pipeline
   >>> decode = Pipeline().from_hex().xor(b"\x42").decode()
   >>> decode("0a272e2e2d")
   'Hello'

**4. A configured engine** applies one policy to many executions
(:doc:`errors-and-safety`):

.. doctest::

   >>> from pychef import Chef, ExecutionPolicy
   >>> chef = Chef(policy=ExecutionPolicy.safe())
   >>> chef.bake("414243", ["From Hex"])
   b'ABC'

:doc:`choosing-an-api` explains which one to use when.

Text and bytes
--------------

Operations accept ``str`` or ``bytes``. Decoders return ``bytes`` (decoded data
is binary until you say it is text); encoders return ``str``. A ``str`` input is
UTF-8 encoded. Use ``bytes`` when the data is binary and ``str`` when it is
text; convert explicitly with ``.decode()`` or ``Pipeline.decode()``. The rules are
in :doc:`data-model`.

Errors and limits
-----------------

Every library error derives from ``PyChefError``. Resource and permission limits
come from an ``ExecutionPolicy``; network access is off unless you grant it:

.. doctest::

   >>> from pychef import ExecutionLimitError, ExecutionPolicy, bake
   >>> try:
   ...     bake("41" * 10, ["From Hex"], policy=ExecutionPolicy(max_input_bytes=4))
   ... except ExecutionLimitError as error:
   ...     print(error.limit)
   max_input_bytes

Find more operations
--------------------

.. doctest::

   >>> from pychef import get_operation_spec, list_operations
   >>> "Gunzip" in list_operations()
   True
   >>> [argument.name for argument in get_operation_spec("To Hex").arguments]
   ['Delimiter', 'Bytes per line']

Each name has a reference page in :doc:`operations/index` with its positional
arguments, defaults, and known limitations. ``pychef.ops.run_operation`` runs any
of them directly.
