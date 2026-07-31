# PyChef

PyChef is a dependency-free, pure-Python implementation of CyberChef's recipe
model and data-transformation operations. It is intended for scripts, tests,
services, and offline tooling that must not require Node.js or JavaScript at
runtime.

```python
from pychef import bake

result = bake(
    "Hello, World!",
    [
        {"op": "To Base64", "args": ["A-Za-z0-9+/="]},
        {"op": "Reverse", "args": ["Character"]},
    ],
)
assert result == b"==QIkxmcvdFIs8GbsVGS"
```

Binary operations preserve `bytes`; text operations return `str`. Set
`return_type="bytes"` or `return_type="str"` to request a final conversion.
Recipes accept the same `{"op": ..., "args": [...]}` shape used by CyberChef,
as well as operation-name strings for argument-free steps.

```python
from pychef import Chef, Recipe

recipe = Recipe(["Gunzip", {"op": "Decode text", "args": ["UTF-8 (65001)"]}])
result = Chef().bake(compressed_data, recipe)
```

## Compatibility status

The pinned reference is CyberChef 11.3.0 at commit
`c56dd23358e948aff9f3f98913818e544227da13`.

This alpha release registers 382 of the 502 upstream operation names (76.1%).
It is not yet a complete CyberChef replacement. The exhaustive name-by-name
matrix is in [COMPATIBILITY.md](COMPATIBILITY.md). Unsupported operations are
not silent stubs: recipes using them raise `UnknownOperationError`.

Compatibility can also be inspected in Python:

```python
from pychef import compatibility_report

report = compatibility_report()
print(len(report.implemented), len(report.missing), report.complete)
```

“Implemented” in the inventory means that an operation is callable. Exact
option-level parity is established incrementally through official CyberChef
vectors ported to pytest. The current suite emphasizes deterministic encodings,
compression, hashes, classical and modern ciphers, binary serialization,
network parsers, date/time conversion, text processing, and recipe behavior.
Browser-only rendering, image/media processing, network requests, heavyweight
public-key/PGP features, and password hashes remain among the missing areas.

## Security and performance

- There are no runtime dependencies and no subprocess or JavaScript bridge.
- The package does not perform network access on import or during ordinary
  operations.
- JWT verification only accepts supported HMAC algorithms and rejects unsigned
  or asymmetric-algorithm confusion.
- Random generators use Python's `secrets` module.
- Parsers validate lengths and fail through `OperationError` instead of silently
  returning corrupt data.
- A `Recipe` can be constructed once and reused to avoid repeat parsing.

Pure-Python cryptographic implementations are provided for compatibility and
testing; use a professionally audited cryptographic package for production key
protection or protocol security.

## Development

Python 3.10 or newer and [uv](https://docs.astral.sh/uv/) are required for
development only:

```console
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv build
```

Pytest enforces branch coverage of at least 75%. Ruff handles formatting and
linting, and `ty` checks the typed public API. The published wheel has no runtime
dependencies.

PyChef is an independent Python port. CyberChef is Crown copyright 2016, GCHQ,
and is licensed under Apache License 2.0. See [NOTICE](NOTICE) and
[LICENSE](LICENSE).
