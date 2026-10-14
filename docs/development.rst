Development
===========

Architecture
------------

Dependencies point in one direction::

   Public API      pychef.ops, pychef (bake, Chef, Recipe, Pipeline), pychef.ctf
        |
   Engine          recipe.py, pipeline.py, execution.py, worker.py, registry.py
        |
   Operations      pychef/operations/by_operation/*.py (one module per operation)
        |
   Shared helpers  pychef/operations/*.py (algorithms), types.py

All entry points execute operations through the same registry and
``ExecutionContext`` (``Recipe.execute`` for recipes, ``Chef`` and ``pychef.ops``;
the equivalent stage loop in ``Pipeline``), so there is exactly one implementation
of every algorithm and one place where limits are enforced. ``pychef.ops`` is a thin typed
layer over that engine. Operation modules are imported lazily on first use.

Testing
-------

.. code-block:: console

   $ uv sync --locked --dev
   $ uv run pytest                # includes coverage (fail under 75%)
   $ uv run ruff check . && uv run ruff format --check .
   $ uv run ty check

Public API, import, typing, installation, example, and documentation-snippet
tests live in ``tests/test_public_*.py``, ``tests/test_examples.py``, and
``tests/test_docs_snippets.py``. ``tests/check_wheel_typing.py`` type-checks a
built wheel in a fresh environment.

Benchmarking
------------

``scripts/benchmark.py`` measures operation throughput. For import cost, run
``python -X importtime -c "import pychef"`` and compare ``len([m for m in sys.modules
if m.startswith("pychef")])`` before and after a change. Compare medians over at
least 15 fresh interpreter runs on a quiet machine and record hardware, operating
system, and Python version with every result (see
``docs/dev/library-dx-release-report.md`` for an example).

Contributing and releasing
--------------------------

See :doc:`contributing`. The release procedure is in ``RELEASING.md`` in the
repository root.
