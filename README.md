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

This alpha release registers all 502 upstream operation names (100% name
coverage). Every registered operation has its own public Python module below
`pychef.operations.by_operation`; a structural test prevents operations from
being registered through a shared catch-all module. Shared algorithm cores are
kept separate where several operations use the same primitive. The exhaustive
name-by-name matrix is in [COMPATIBILITY.md](COMPATIBILITY.md).

Compatibility can also be inspected in Python:

```python
from pychef import compatibility_report

report = compatibility_report()
print(len(report.implemented), len(report.missing), report.complete)
```

“Implemented” in the inventory means that an operation is callable. Exact
option-level parity is established incrementally through official CyberChef
vectors ported to pytest. The current suite covers deterministic encodings,
compression, hashes, classical and modern ciphers, binary serialization,
recipe flow control, public-key operations, raster images, media metadata,
charts, coordinates, network requests, Argon2/Bcrypt, SM2, PGP workflows,
machine-code inspection, JSON query languages, OCR, and YARA rules.

Name coverage is deliberately separate from reference parity. Some callable
operations are dependency-free compatibility fallbacks or support a documented
format subset. Remaining broad parity boundaries include decoding arbitrary QR
symbols; palette/interlaced PNG, progressive/CMYK JPEG, and compressed TIFF;
complete Typex/SIGABA/Lorenz machine presets; full JavaScript/Jq/Jsonata and
YARA grammars; general-purpose OCR; complete instruction decoding; AMF3
externalizable values; and interoperable OpenPGP packets. The MD6, Snefru,
Streebog, Whirlpool, RIPEMD, Twofish, GOST, CTPH, SSDEEP, CRC, JPEG baseline,
GIF first-frame, and uncompressed TIFF paths now have real Python
implementations and official vectors rather than compatibility placeholders.

## Security and performance

- There are no runtime dependencies and no subprocess or JavaScript bridge.
- The package does not perform network access on import. Only explicit
  `HTTP request` and `DNS over HTTPS` operations access the network; they reject
  credentials in URLs and local/private/reserved destinations.
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

Pytest enforces branch coverage of at least 75%; the current suite contains
more than 830 tests and reports over 85% branch coverage. Ruff handles
formatting and linting, and `ty` checks the typed public API. The published
wheel has no runtime dependencies.

PyChef is an independent Python port. CyberChef is Crown copyright 2016, GCHQ,
and is licensed under Apache License 2.0. See [NOTICE](NOTICE),
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md), and [LICENSE](LICENSE).
