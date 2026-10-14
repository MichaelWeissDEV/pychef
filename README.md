# PyChef

[![Documentation Status](https://readthedocs.org/projects/cyberchef-py/badge/?version=latest)](https://cyberchef-py.readthedocs.io/en/latest/?badge=latest)

PyChef is an unofficial, dependency-free, pure-Python implementation of CyberChef's recipe
model and data-transformation operations. It is intended for scripts, tests,
services, and offline tooling that must not require Node.js or JavaScript at
runtime.

## Installation

The PyPI distribution is named `cyberchef-py`; the Python import is `pychef`.

```console
python -m pip install cyberchef-py
```

With uv:

```console
uv add cyberchef-py
```

Python 3.10 or newer is required. The published package has no runtime
dependencies.

Run the complete local example from a repository checkout:

```console
uv sync --locked
uv run python examples/quickstart.py
```

## Documentation

The Sphinx documentation includes beginner guides, recipes, pipelines, CTF and
packet tooling, the public Python API, compatibility boundaries, and a separate
reference page for every registered operation. Read it at
[cyberchef-py.readthedocs.io](https://cyberchef-py.readthedocs.io/en/latest/);
its source is in [docs](docs/index.rst).

Build the same strict HTML documentation used by Read the Docs and CI:

```console
uv sync --locked --group docs
uv run python docs/_scripts/generate_operation_docs.py --check
uv run sphinx-build -W --keep-going -b html docs docs/_build/html
```

The repository contains a version 2 `.readthedocs.yaml`; importing the GitHub
repository into Read the Docs is enough to use the pinned uv environment and
Sphinx configuration.

## Quick start

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

## Fluent pipelines

`Pipeline` builds immutable, reusable transformations. Use `.then()` for any
registered CyberChef operation or the typed convenience methods for common CTF
workflows. Pipelines compose with `|`; a value can also be piped into one.

```python
from pychef import Pipeline

decode = Pipeline().from_hex().xor(b"\x42").decode()
assert decode("0a272e2e2d") == "Hello"
assert "0a272e2e2d" | decode == "Hello"

base64_decode = Pipeline().from_base64()
combined = decode | Pipeline().to_base64()
results = combined.transform_many(["0a272e2e2d", "152d302e26"])
```

Branches receive the same current value. Their outputs can be concatenated as
long as all branches return the same type as the separator:

```python
hash_line = Pipeline().concat(
    Pipeline().digest("md5"),
    Pipeline().digest("sha256"),
    separator=":",
)
print(hash_line(b"flag"))

trace = decode.trace("0a272e2e2d")
print([(step.name, step.output) for step in trace])
```

Python callables and structured data are valid stages too. `.select()` walks
nested dictionary keys and sequence indexes. A pipeline that only contains
CyberChef operations can be recovered as `.recipe`.

## CTF and binary helpers

The top-level API includes pwntools-style integer packing, explicit endian
variants, byte XOR, de Bruijn patterns, dumps, hashing, and flattening:

```python
from pychef import cyclic, cyclic_find, flat, p32, p32be, sha256, u64

payload = flat(b"A" * 40, p32(0xDEADBEEF), p32be(0x1337))
address = u64(leaked_bytes)
offset = cyclic_find(crashed_value)
fingerprint = sha256(payload)
```

`p8`, `p16`, `p32`, and `p64` use little endian by default; `p16le`/`p16be`,
`p32le`/`p32be`, `p64le`/`p64be`, and matching `u*` functions are explicit.
`pack()` and `unpack()` support arbitrary byte-aligned widths and signed
integers. `swap_endian()` reverses each fixed-width word.

AES helpers accept CBC, ECB, CFB, OFB, CTR, and authenticated GCM. Non-ECB
modes require an explicit IV/nonce. GCM appends its 16-byte tag by default;
detached tags are available through `aes_gcm_encrypt()`:

```python
from pychef import Pipeline, aes_decrypt, aes_encrypt, aes_gcm_encrypt

ciphertext = aes_encrypt(data, key, mode="CBC", iv=iv, padding="pkcs7")
assert aes_decrypt(ciphertext, key, mode="CBC", iv=iv) == data

ciphertext, tag = aes_gcm_encrypt(data, key, iv=nonce, aad=b"header")
round_trip = (
    Pipeline()
    .aes_encrypt(key, mode="GCM", iv=nonce, aad=b"header")
    .aes_decrypt(key, mode="GCM", iv=nonce, aad=b"header")
)
assert round_trip(data) == data
```

Keys, IVs, and tags are raw bytes by default. Pass `key_format="hex"`,
`iv_format="hex"`, or `tag_format="hex"` for textual hexadecimal material.

## Packets and capture files

`parse_capture()` auto-detects classic PCAP and PCAPNG and returns ordinary
Python dictionaries. Ethernet/VLAN, Linux cooked captures, loopback/raw IP,
ARP, IPv4, IPv6 extension headers, ICMP, TCP options, UDP, DNS, and recognizable
HTTP/TLS records are decoded recursively. Unsupported link or application data
remains available as bytes.

```python
from pychef import Pipeline, parse_capture, read_capture

capture = read_capture("challenge.pcap")
first_packet = capture["packets"][0]["decoded"]

source = (Pipeline().parse_capture().select("packets", 0, "decoded", "network", "source"))(
    pcap_bytes
)
```

Parsers enforce packet-count, packet-size, and file-size limits. `json_safe()`
or `packet_json()` converts retained byte strings to `{hex, length}` objects for
JSON output without losing their sizes.

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

## Security and execution policy

PyChef offers fine-grained execution safety and resource controls:

- **Configurable Execution Policies**:
  `ExecutionPolicy.safe()` is the default profile, with conservative budgets and network access completely disabled. Other profiles include `untrusted()`, `unrestricted()`, and `permissive()`.
  Limits can be explicitly customized or disabled (`None` disables a numeric limit):

  ```python
  from pychef import ExecutionPolicy, NetworkPolicy, bake

  policy = ExecutionPolicy.safe().with_overrides(
      max_memory_bytes=64 * 1024**2,
      max_steps=5_000,
      network=NetworkPolicy.public_only(
          timeout_seconds=5.0,
          max_redirects=3,
      ),
  )
  result = bake(data, recipe, policy=policy)
  ```

- **SSRF & DNS-Pinning Protection**:
  Network operations validate IP destinations against private, loopback, link-local, and reserved ranges. Socket connections are pinned directly to validated IP addresses to prevent DNS rebinding. Redirects re-validate every hop and automatically strip sensitive headers across origins.
- **Process Isolation (`IsolatedWorker`)**:
  Recipes can be executed in an isolated child process via `IsolatedWorker` or `bake_isolated()`. On Linux, hard OS-level memory limits (`RLIMIT_AS`/`RLIMIT_DATA`) can be enforced.
- **Secret Redaction**:
  Exceptions (`OperationError`, `PyChefError`) sanitize error messages and arguments to prevent leaking sensitive keys, passwords, or tokens in logs or serialization.

## Development

Python 3.10 or newer and [uv](https://docs.astral.sh/uv/) are required for
development:

```console
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv build
```

Pytest enforces branch coverage of at least 75%; the test suite contains
over 1,120 tests and exceeds 85% branch coverage. Ruff handles
formatting and linting, and `ty` checks the typed public API. The published
wheel has no runtime dependencies.

PyChef is an independent Python port. CyberChef is Crown copyright 2016, GCHQ,
and is licensed under Apache License 2.0. See [NOTICE](NOTICE),
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md), and [LICENSE](LICENSE).
