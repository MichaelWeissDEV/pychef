Contributing to PyChef and its documentation
============================================

Set up the repository
---------------------

.. code-block:: console

   $ git clone https://github.com/MichaelWeissDEV/pychef.git
   $ cd pychef
   $ uv sync --locked --dev --group docs

Run the project checks
----------------------

.. code-block:: console

   $ uv run pytest
   $ uv run ruff format --check .
   $ uv run ruff check .
   $ uv run ty check

Build the documentation
-----------------------

.. code-block:: console

   $ uv run sphinx-build -W --keep-going -b html docs docs/_build/html

Open ``docs/_build/html/index.html`` in a browser. ``-W`` turns Sphinx warnings
into build failures, while ``--keep-going`` reports all warnings in one run.

Operation reference generation
------------------------------

Do not hand-edit files below ``docs/operations/reference`` or
``docs/operations/categories``. They are generated from the live Python registry
and the pinned metadata file:

.. code-block:: console

   $ uv run python docs/_scripts/generate_operation_docs.py
   $ uv run python docs/_scripts/generate_operation_docs.py --check

The metadata extractor is used only when intentionally updating the pinned
CyberChef version. Give it a local checkout of that exact upstream commit:

.. code-block:: console

   $ uv run python docs/_scripts/extract_cyberchef_metadata.py \
       /path/to/CyberChef docs/_data/cyberchef_operations.json

The extractor parses source metadata as text and does not execute JavaScript.
Regenerate the pages, inspect changed defaults and choices, and run the complete
test and documentation suites before committing an upstream update.

Document a changed operation
----------------------------

When an implementation gains an option or changes a default:

#. add or update pytest vectors for that exact behavior;
#. keep positional argument access explicit in its Python implementation;
#. add a curated runnable example to the generator when a default-only template
   would be unsafe or misleading;
#. update a known limitation when the supported scope changes;
#. regenerate and run the strict Sphinx build.
