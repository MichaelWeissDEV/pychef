Frequently asked questions
==========================

Why do I install ``cyberchef-py`` but import ``pychef``?
--------------------------------------------------------

PyPI distribution names and Python package names are separate. The published
distribution is ``cyberchef-py``; its stable import package is ``pychef``.

Does PyChef need Node.js or JavaScript?
---------------------------------------

No. The installed library is Python. The generated documentation metadata is
derived from a pinned CyberChef source checkout during maintenance, but normal
installation, import, recipes, pipelines, tests, and documentation builds do not
execute or ship a Node.js bridge.

Why did an operation return ``bytes`` instead of ``str``?
---------------------------------------------------------

The operation produced binary data. Add ``Decode text`` at a known text boundary
or request ``return_type="str"`` for the final recipe result. See
:doc:`data-model`.

How do I pass operation options?
--------------------------------

Arguments are positional. In a recipe use ``{"op": "Name", "args": [...]}``;
in a pipeline use ``Pipeline().then("Name", ...)``. Copy the order and accepted
values from the operation's reference page.

How do I chain an operation with normal Python code?
----------------------------------------------------

Use ``Pipeline.apply(callable)``. It can consume or produce dictionaries,
integers, lists, bytes, text, or custom objects. Registered operations themselves
expect text or bytes.

How do I see intermediate values?
---------------------------------

Call ``pipeline.trace(value)``. Each returned ``PipelineTrace`` contains the stage
name, input, and output.

Does 100% operation-name coverage mean exact CyberChef parity?
--------------------------------------------------------------

No. It means all names in the pinned inventory are registered. Exact parity is
verified option by option through tests. Read :doc:`compatibility` and the warning
on the relevant operation page.

Can I use the AES implementation for production secrets?
---------------------------------------------------------

PyChef targets compatibility, education, testing, and CTFs. Use a professionally
audited cryptographic library and protocol for production protection of secrets.

How do I update the documentation after changing an operation?
---------------------------------------------------------------

Run the generator and strict build shown in :doc:`contributing`. CI also verifies
that generated pages are current and that Sphinx emits no warnings.
