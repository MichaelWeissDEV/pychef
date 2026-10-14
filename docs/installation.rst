Installation
============

Requirements
------------

* Python 3.10, 3.11, 3.12, 3.13 or 3.14 (CPython; PyPy is not part of the CI matrix).
* Linux, macOS, or Windows.
* No runtime dependencies on Linux and macOS. On **Windows** the ``tzdata`` package
  is installed automatically (marker ``platform_system == 'Windows'``) because Windows
  ships no IANA time zone database that the date and time operations need.

Distribution name versus import name
------------------------------------

The project is published on PyPI as **cyberchef-py** (the name ``pychef`` was not
available) and is imported as **pychef**:

.. code-block:: console

   $ python -m pip install cyberchef-py
   $ python -c "import pychef; print(pychef.__version__)"

With uv:

.. code-block:: console

   $ uv add cyberchef-py

Pin a version in applications:

.. code-block:: console

   $ python -m pip install "cyberchef-py==0.2.0"

Use ``cyberchef-py>=0.2,<0.3`` in a library's dependencies. PyChef is pre-1.0, so
minor versions may change behaviour; read :doc:`versions` and the changelog.

Verify the installation
-----------------------

.. code-block:: python

   import pychef
   from pychef.ops import from_hex, to_base64

   assert to_base64(from_hex("414243")) == "QUJD"
   print(pychef.__version__, len(pychef.list_operations()))

The package ships ``py.typed``; type checkers and IDEs read its annotations from the
installed package.

Development version
-------------------

.. code-block:: console

   $ python -m pip install "git+https://github.com/MichaelWeissDEV/pychef"

Documentation for the development branch is at ``/en/latest/``; see :doc:`versions`.
