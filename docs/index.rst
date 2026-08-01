PyChef documentation
====================

PyChef is an unofficial, pure-Python data-transformation library inspired by
CyberChef. It runs recipes and reusable pipelines inside normal Python scripts,
tests, services, notebooks, and CTF tooling. The published package has no runtime
dependency on Node.js or JavaScript.

The PyPI distribution is named ``cyberchef-py``. The import is named ``pychef``.
PyChef currently registers 502 operation names from the pinned CyberChef 11.3.0
inventory. Name coverage and exact option-level compatibility are deliberately
reported separately; read :doc:`compatibility` before relying on an uncommon
format or protocol variant.

Start here
----------

* :doc:`getting-started` installs the package and performs a first transformation.
* :doc:`data-model` explains when PyChef uses ``str`` and when it uses ``bytes``.
* :doc:`recipes` explains CyberChef-compatible recipe dictionaries.
* :doc:`pipelines` explains immutable, composable Python transformations.
* :doc:`operations/index` lists every operation, its arguments, status, and examples.
* :doc:`ctf-tools` covers packing, endianness, XOR, hashes, cyclic patterns, and AES.
* :doc:`packets` turns network packets, PCAP, and PCAPNG into Python dictionaries.

.. toctree::
   :maxdepth: 2
   :caption: Learn

   getting-started
   data-model
   recipes
   pipelines
   examples
   ctf-tools
   packets
   errors-and-safety

.. toctree::
   :maxdepth: 3
   :caption: Reference

   operations/index
   api/index
   compatibility
   attribution

.. toctree::
   :maxdepth: 2
   :caption: Project

   contributing
   faq

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
