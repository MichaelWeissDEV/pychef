Custom registries
=================

An :class:`~pychef.OperationRegistry` maps operation names to functions. The default
``pychef.registry`` contains all 502 built-in operations (loaded lazily). Create your
own registry to add operations or to run a restricted set.

.. doctest::

   >>> from pychef import Chef, Operation, OperationRegistry
   >>> from pychef.types import to_text
   >>> def shout(value, args):
   ...     return to_text(value).upper() + (str(args[0]) if args else "!")
   >>> private = OperationRegistry(manifest={})   # empty: no built-in operations
   >>> private.register(Operation("Shout", shout, category="Examples"))
   >>> Chef(operation_registry=private).bake("hi", [{"op": "Shout", "args": ["?"]}])
   'HI?'
   >>> private.names()
   ('Shout',)

Operation functions receive ``(value, args)`` -- the input (``str`` or ``bytes``) and
the positional arguments -- and return ``str`` or ``bytes``. A registry created with
the default manifest still loads built-ins on demand and falls back to the global
registry. Registries are picklable, so they can be passed to
``IsolatedWorker(operation_registry=...)``; the functions must be importable
module-level callables for that.

Custom operations run with the host's permissions; the execution policy limits steps,
input and output size, and the deadline, but cannot restrict what your function does.
