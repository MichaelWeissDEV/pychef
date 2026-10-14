Tracing
=======

Two tools show what happened during an execution.

``Pipeline.trace`` keeps the input and output of every stage:

.. doctest::

   >>> from pychef import Pipeline
   >>> for stage in Pipeline().from_hex().to_base64().trace("414243"):
   ...     print(stage.name, stage.input_size, "->", stage.output_size)
   From Hex 6 -> 3
   To Base64 3 -> 4

``Chef.bake_result(..., trace=True)`` returns a :class:`~pychef.BakeResult` whose
``trace`` holds one :class:`~pychef.TraceStep` per executed step (operation, step
index, branch path, input/output type and size, duration, error type). Trace steps
never contain the data itself, only types and sizes. Trace memory is bounded by
``ExecutionPolicy.max_trace_bytes``; ``Pipeline.trace(max_preview_bytes=...)``
truncates stored previews.

Nested calls and branches are recorded in the same trace with their ``branch_path``.
