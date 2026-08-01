Recipes
========

A recipe is an ordered, validated collection of CyberChef operation steps. Use a
recipe when you need a serializable transformation or already have recipe-shaped
data from CyberChef.

Accepted step forms
-------------------

An argument-free operation can be written as a string:

.. code-block:: python

   recipe = ["Gunzip", "MD5"]

Use a dictionary whenever the operation has arguments:

.. code-block:: python

   recipe = [
       {"op": "From Hex", "args": ["Auto"]},
       {"op": "XOR", "args": [{"option": "Hex", "string": "42"}, "Standard", False]},
       {"op": "Decode text", "args": ["UTF-8 (65001)"]},
   ]

The complete dictionary form is:

.. code-block:: python

   step = {
       "op": "Operation name",
       "args": [],
       "disabled": False,
       "breakpoint": False,
   }

``disabled`` skips a step. ``breakpoint`` stops before a step. ``Comment`` is a
no-op. The structured :class:`pychef.RecipeStep` type is also accepted.

Validate and reuse a recipe
---------------------------

Construct :class:`pychef.Recipe` once when processing many values. This validates
the shape once and avoids reparsing it for every call.

.. code-block:: python

   from pychef import Chef, Recipe

   recipe = Recipe(
       [
           {"op": "From Base64", "args": ["A-Za-z0-9+/=", True, False]},
           {"op": "Decode text", "args": ["UTF-8 (65001)"]},
       ]
   )
   chef = Chef()

   assert chef.bake("SGVsbG8=", recipe) == "Hello"
   assert chef.bake("V29ybGQ=", recipe) == "World"

Inspect errors and progress
---------------------------

``Chef.bake_result`` returns timing, output type, completed-step count, and an
optional error. Set ``raise_errors=False`` when failure is expected and should be
inspected instead of raised.

.. code-block:: python

   from pychef import Chef

   outcome = Chef().bake_result("not hex", ["From Hex"], raise_errors=False)
   if outcome.error is not None:
       print(type(outcome.error).__name__, outcome.progress, outcome.duration_ms)

Flow-control operations
-----------------------

Recipes implement CyberChef-style ``Label``, ``Jump``, ``Conditional Jump``,
``Register``, ``Fork``, ``Subsection``, ``Merge``, and ``Return`` behavior.
Use these only when a serializable CyberChef-style recipe needs flow control.
For normal Python code, a :doc:`pipeline <pipelines>` plus Python callables is
usually easier to read and type-check.

Convert between pipelines and recipes
-------------------------------------

A pipeline containing only registered operation stages exposes ``.recipe``:

.. code-block:: python

   from pychef import Pipeline

   pipeline = Pipeline().then("From Hex", "Auto").then("To Base64", "A-Za-z0-9+/=")
   recipe = pipeline.recipe

If the pipeline contains ``apply``, branching, packet parsing, hashing helper
stages, or other Python-only stages, ``.recipe`` raises :class:`pychef.RecipeError`
because those stages cannot be represented as CyberChef recipe dictionaries.
