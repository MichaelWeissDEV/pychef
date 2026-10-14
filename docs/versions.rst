Documentation versions
======================

This documentation is built per version on Read the Docs. Use the version menu
(bottom-left in the sidebar, or the URL) to choose:

.. list-table::
   :header-rows: 1

   * - Version
     - URL
     - Content
   * - ``stable``
     - https://cyberchef-py.readthedocs.io/en/stable/
     - The newest **released** version. Use this with ``pip install cyberchef-py``.
   * - ``latest``
     - https://cyberchef-py.readthedocs.io/en/latest/
     - The development branch (``main``); may describe unreleased features.
   * - ``vX.Y.Z``
     - https://cyberchef-py.readthedocs.io/en/v0.2.0/
     - Exactly the documentation of that release tag; permanent.

The page title and the sidebar show the PyChef version that was built. If an API in
these pages is missing from your installation, compare ``pychef.__version__`` with
the version of the documentation you are reading.

Which version introduced what
-----------------------------

* **0.2.0**: ``pychef.ops`` (direct operations), ``Recipe.to_json`` / ``from_json``,
  shared ``ExecutionContext`` for nested calls, ``NetworkPolicy`` and the
  ``ExecutionPolicy`` profiles, ``IsolatedWorker``, lazy operation loading, typed
  ``py.typed`` API, Windows ``tzdata`` dependency.
* **0.1.x**: recipes, pipelines, CTF helpers, packet parsing, the operation catalogue.

The complete history is in the `changelog
<https://github.com/MichaelWeissDEV/pychef/blob/main/CHANGELOG.md>`_.
