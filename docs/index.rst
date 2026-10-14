PyChef documentation
====================

PyChef is an unofficial, pure-Python data-transformation library inspired by
CyberChef. Use it as a normal Python library: call single operations as
functions, run CyberChef recipes, or build reusable pipelines. It has no runtime
dependencies (except ``tzdata`` on Windows) and needs no Node.js.

The PyPI distribution is ``cyberchef-py``; the import is ``pychef``.
PyChef registers 502 operation names from the pinned CyberChef 11.3.0 inventory.
Name coverage and exact option-level compatibility are reported separately; read
:doc:`compatibility` before relying on an uncommon format or protocol variant.

.. code-block:: python

   from pychef import Pipeline, bake
   from pychef.ops import from_hex, to_base64

   to_base64(from_hex("414243"))                     # direct operations
   bake("414243", ["From Hex", "To Base64"])         # recipes
   Pipeline().from_hex().to_base64()("414243")       # pipelines

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   getting-started
   choosing-an-api
   data-model

.. toctree::
   :maxdepth: 2
   :caption: User guide

   direct-operations
   recipes
   pipelines
   errors-and-safety
   examples

.. toctree::
   :maxdepth: 2
   :caption: Cookbook

   cookbook
   ctf-tools
   packets

.. toctree::
   :maxdepth: 3
   :caption: Reference

   api/index
   operations/index
   compatibility
   attribution

.. toctree::
   :maxdepth: 2
   :caption: Development

   development
   contributing
   faq

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
