Getting started
===============

Requirements
------------

PyChef requires Python 3.10 or newer. The wheel contains the Python
implementation and has no mandatory runtime dependencies.

Install from PyPI
-----------------

The distribution and import names are intentionally different:

.. code-block:: console

   $ python -m pip install cyberchef-py

or with uv:

.. code-block:: console

   $ uv add cyberchef-py

Import ``pychef``, not ``cyberchef_py``:

.. code-block:: python

   import pychef

   print(pychef.__version__)
   print(len(pychef.list_operations()))

Your first recipe
-----------------

``bake`` applies each operation in order. Operation names are case-sensitive and
match their entries in the :doc:`operations/index`.

.. code-block:: python

   from pychef import bake

   result = bake(
       "Hello, World!",
       [
           {"op": "To Base64", "args": ["A-Za-z0-9+/="]},
           {"op": "Reverse", "args": ["Character"]},
       ],
   )

   assert result == b"==QIkxmcvdFIs8GbsVGS"

The first operation returns bytes and the second keeps that binary output. This
is expected. See :doc:`data-model` for explicit final conversion.

Your first pipeline
-------------------

A pipeline is useful when the same transformation is applied repeatedly:

.. code-block:: python

   from pychef import Pipeline

   decode = Pipeline().from_hex().xor(b"\x42").decode()

   assert decode("0a272e2e2d") == "Hello"
   assert decode("152d302e26") == "World"

Pipelines are immutable. Calling ``then``, ``xor``, or another chaining method
returns a new pipeline and leaves the old instance unchanged.

Discover operations
-------------------

.. code-block:: python

   from pychef import list_operations, registry

   for name in list_operations():
       print(name)

   to_hex = registry.get("To Hex")
   print(to_hex.category)
   print(to_hex.run(b"ABC", ("None", 0)))

For each name, its reference page documents positional argument order, defaults,
known boundaries, a recipe call, a pipeline call, and the dedicated Python module.
