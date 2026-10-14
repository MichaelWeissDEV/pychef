# PyChef 0.2.0

First release since 0.1.1. Install with `python -m pip install "cyberchef-py==0.2.0"` (import as `pychef`; Python 3.10-3.14).

## Highlights

- **Direct operations (`pychef.ops`)**: 22 typed functions with keyword-only options -- `from_hex`, `to_hex`, `from_base64`, `to_base64`, `from_base32`, `to_base32`, `url_encode`, `url_decode`, `html_encode`, `html_decode`, `rot13`, `reverse`, `xor`, `gzip_compress`, `gzip_decompress`, `md5`, `sha1`, `sha256`, `sha512`, `digest`, plus `run_operation()` for any of the 502 registered operations and `using_policy()`.
- **Recipes and pipelines**: `Recipe.to_json()` / `from_json()` / `to_config()`; `Pipeline.concat()` branches now run in the caller's execution context; all convenience methods documented.
- **Execution policies**: `ExecutionPolicy` profiles (`safe`, `untrusted`, `unrestricted`, `permissive`), explicit `None` to disable a limit, and a **shared `ExecutionContext`**: nested `bake`/`Chef`/`Pipeline`/`pychef.ops` calls inside a running execution share its step budget, deadline and trace; a conflicting policy is rejected.
- **Network control**: `NetworkPolicy` (`disabled` by default), SSRF and DNS-rebinding protection, per-hop redirect validation, credential stripping across origins, redirect bodies are no longer drained.
- **Worker isolation**: `IsolatedWorker` / `bake_isolated` with deadlines that cover the whole IPC message, bounded cleanup, clear errors for malformed results; hard memory limits on Linux.
- **Windows**: time zone operations work after a normal install (`tzdata` is installed automatically on Windows); CI covers Linux 3.10-3.14, macOS and Windows.
- **Typing and import**: `py.typed`, typed overloads, lazy operation loading (`import pychef` loads 13 modules instead of 18).
- **Documentation**: reorganised, versioned (`stable`, `latest`, per tag), direct-operations guide, cookbook, execution-policy, tracing and custom-registry guides, tested examples.

## Compatibility with CyberChef

All 502 CyberChef 11.3.0 operation names are registered. "Registered" means callable, not byte-for-byte identical for every option; known boundaries (for example QR decoding, progressive JPEG, full OpenPGP interoperability) are listed in the documentation. PyChef is a Python library only: no GUI, server or JavaScript runtime. `Pipeline.apply` runs trusted Python code and is not a sandbox; resource limits are cooperative except in `IsolatedWorker` on Linux.

Full changelog: https://github.com/MichaelWeissDEV/pychef/blob/v0.2.0/CHANGELOG.md
Documentation: https://cyberchef-py.readthedocs.io/en/v0.2.0/
