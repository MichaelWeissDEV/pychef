# PyChef

[![Documentation Status](https://readthedocs.org/projects/cyberchef-py/badge/?version=latest)](https://cyberchef-py.readthedocs.io/en/latest/?badge=latest)
[![PyPI](https://img.shields.io/pypi/v/cyberchef-py)](https://pypi.org/project/cyberchef-py/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/cyberchef-py?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=BLUE&left_text=downloads)](https://pepy.tech/projects/cyberchef-py)
[![Python](https://img.shields.io/pypi/pyversions/cyberchef-py)](https://pypi.org/project/cyberchef-py/)
[![License](https://img.shields.io/pypi/l/cyberchef-py)](LICENSE)

PyChef is an unofficial, pure-Python library for CyberChef-style
data transformations. Call single operations as plain functions, run
CyberChef-compatible recipes, or compose reusable pipelines. It needs no Node.js
at runtime and applies safe resource limits by default. The package is typed
(`py.typed`).

## Installation

The PyPI distribution is named `cyberchef-py`; the Python import is `pychef`.

```console
python -m pip install cyberchef-py
```

or

```console
uv add cyberchef-py
```

Pin a version in applications with `cyberchef-py==0.2.0`. Python 3.10-3.14 is supported. There are no runtime dependencies on Linux and macOS; on Windows the
`tzdata` time zone database is installed automatically (Windows has no system copy).

```python
import pychef

print(pychef.__version__)
```

## Quick start

The same transformation through the three everyday entry points:

```python
from pychef import Pipeline, bake
from pychef.ops import from_hex, to_base64

to_base64(from_hex("414243"))  # direct operations -> 'QUJD'
bake("414243", ["From Hex", "To Base64"])  # recipe            -> 'QUJD'
Pipeline().from_hex().to_base64()("414243")  # pipeline          -> 'QUJD'
```

## Direct operations

`pychef.ops` offers typed functions with named, keyword-only options. They
run the registered operation through the regular engine, so the safe default
policy (bounded resources, no network) applies exactly as for `bake()`.

```python
from pychef.ops import from_base64, rot13, sha256, to_hex, xor, run_operation

to_hex(b"ABC", delimiter="Space")  # '41 42 43'
xor(b"\x0a\x27", b"\x42")  # b'He'
sha256("abc")  # 'ba7816bf...'
run_operation("To Base64", b"Hello")  # any of the 502 operations
```

See the [Direct operations guide](https://cyberchef-py.readthedocs.io/en/stable/direct-operations.html).

## Recipes

Recipes use the CyberChef `{"op": ..., "args": [...]}` shape and can be stored
as JSON.

```python
from pychef import Chef, ExecutionPolicy, Recipe

recipe = Recipe(["From Hex", {"op": "To Base64", "args": ["A-Za-z0-9+/="]}])
chef = Chef(policy=ExecutionPolicy.safe())
chef.bake("414243", recipe)  # 'QUJD'
Recipe.from_json(recipe.to_json())  # round trip
```

## Pipelines

`Pipeline` is immutable and reusable, mixes operations with your own Python
functions, and supports branches, batching, streaming, and tracing.

```python
from pychef import Pipeline

decode = Pipeline().from_hex().xor(b"\x42").decode()
decode("0a272e2e2d")  # 'Hello'
list(decode.iter_transform(["0a272e2e2d", "152d302e26"]))
```

## Features

- 502 registered operation names from the pinned CyberChef 11.3.0 inventory.
- Execution policies for memory, input, output, steps, branches, time, and network
  (`ExecutionPolicy`, `NetworkPolicy`), plus `IsolatedWorker` for process isolation.
- CTF and binary helpers (`pychef.ctf` re-exported at top level): packing,
  endianness, XOR, de Bruijn patterns, hashes, hexdumps, AES.
- Packet and capture parsing (`parse_capture` for PCAP/PCAPNG, DNS, TCP, UDP, ...).
- Structured, secret-redacting errors.

## CyberChef compatibility

All 502 upstream operation names are registered ([COMPATIBILITY.md](COMPATIBILITY.md)).
"Registered" means callable; it does **not** mean every option combination is
byte-for-byte identical to CyberChef. Known broad boundaries (for example QR
decoding, progressive JPEG, full OpenPGP interoperability) are listed in the
[compatibility page](https://cyberchef-py.readthedocs.io/en/stable/compatibility.html).
PyChef is a library only: there is no GUI, web server, or JavaScript runtime.

## Documentation

Full documentation, including the cookbook, API reference, and a page for every
operation: [cyberchef-py.readthedocs.io](https://cyberchef-py.readthedocs.io/en/stable/).
Documentation is versioned: `stable` (latest release), `latest` (development), and one
per release tag such as `v0.2.0`. Changes are listed in the [changelog](CHANGELOG.md).
Runnable scripts are in [examples](examples).

## Security notes

- Defaults are conservative: `ExecutionPolicy.safe()` limits resources and denies
  network access. Network access must be granted through a `NetworkPolicy`; requests
  are SSRF-checked and DNS-pinned.
- `Pipeline.apply()` runs arbitrary Python you provide. It is for trusted code, not
  a sandbox.
- Cooperative limits are checked between steps. For untrusted recipes use
  `IsolatedWorker`; hard memory limits are available on Linux only.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Contributing

```console
uv sync --locked --dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run ty check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASING.md](RELEASING.md).

## License

Apache-2.0. PyChef is an independent Python port. CyberChef is Crown copyright
2016, GCHQ, and is licensed under Apache License 2.0. See [LICENSE](LICENSE),
[NOTICE](NOTICE), and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
