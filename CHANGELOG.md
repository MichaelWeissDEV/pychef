# Changelog

All notable changes to this project are documented here. Releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-14

First release since 0.1.1.

### Added

- **Direct operations API (`pychef.ops`)**: typed, keyword-option functions for common
  transformations (`from_hex`, `to_hex`, `from_base64`, `to_base64`, `from_base32`,
  `to_base32`, `url_encode`, `url_decode`, `html_encode`, `html_decode`, `rot13`,
  `reverse`, `xor`, `gzip_compress`, `gzip_decompress`, `md5`, `sha1`, `sha256`, `sha512`,
  `digest`) plus `run_operation()` for any registered operation and `using_policy()` to
  scope an `ExecutionPolicy`. The functions run through the regular engine, so
  `ExecutionPolicy.safe()` (no network, bounded resources) applies exactly as for `bake()`.
  `pychef.ops` is also reachable lazily as `pychef.ops`.
- `Recipe.to_config()`, `Recipe.to_json()`, `Recipe.from_json()`, `len()` and a readable `repr()`.
- Docstrings for all `Pipeline` convenience methods and the `pychef.ctf` hash helpers.
- Documentation: reorganised navigation, "Recipes, pipelines, or direct operations",
  Direct operations guide, cookbook, development notes, execution/worker API reference;
  documentation snippets and all `examples/` scripts are tested.
- Installed-wheel type-check (`tests/check_wheel_typing.py`), extended `tests/smoke_test.py`,
  and a macOS/Windows CI job.
- **HTTP Redirect Hardening & Credential Protection**:
  - Implemented origin normalization and verification across redirect chains (`_get_origin`).
  - Automatically strip sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Cookie2`, and user-configured `sensitive_headers`) whenever an HTTP redirect crosses origin boundaries (scheme, port, or normalized host).
  - Enforced per-hop destination policy re-evaluation in `_SafeRedirectHandler`.
  - Added support for `max_redirects=None` (unbounded redirects) in `NetworkPolicy` by overcoming standard library urllib `None` comparison limitations.
- **Enhanced SSRF & DNS-Pinning Protection**:
  - Added `PolicyDecision` enum (`ALLOW`, `DENY`, `NEEDS_RESOLUTION`) and `NetworkPolicy.evaluate_pre_resolution()` to prevent premature DNS queries and properly resolve hostnames matching `allowed_subnets`.
  - Added IPv6 mapped address unwrapping (`::ffff:x.x.x.x`, 6to4, NAT64) to strictly enforce IPv4 subnet and host deny lists against IPv6-mapped representations.
  - Reject mixed DNS responses if any resolved IP violates the network policy.
- **ExecutionPolicy Explicit Overrides & Sentinel Semantics**:
  - Introduced `_UNSET` sentinel ensuring that explicit `None` arguments (e.g. `with_overrides(max_memory_bytes=None, allow_network=None)`) reliably disable limits rather than being overwritten by truthiness defaults.
  - Added strict parameter validation rejecting invalid negative or non-integer limits.
- **Error Handling & Data Confidentiality**:
  - Added `safe_message` property to `PyChefError` and included it in structured `to_dict()` outputs.
  - Enhanced `_sanitize_error_message()` across recipe and pipeline execution to recursively redact secrets from intermediate values, inputs, and credential patterns (`Bearer`, `Basic`, `cookie=`, `api_key:`, passwords).
- **Cycle-Safe Pipeline Tracing & Memory Budgeting**:
  - Implemented cycle-safe recursive container measurement (`_measure_trace_size`) preventing recursion errors on circular references and shared objects.
  - Enhanced UTF-8 preview slicing (`_truncate_preview`) to cleanly truncate at character boundaries without splitting multi-byte code points.
  - Charged actually stored preview bytes against `policy.max_trace_bytes` rather than logical input/output sizes.
- **IsolatedWorker Hardening & Concurrency Protection**:
  - Added internal concurrency lock preventing race conditions from concurrent `run()` calls on the same worker instance.
  - Hardened process startup cleanup with try/finally to safely reap processes and close IPC pipes on initialization failure.
  - Differentiated unexpected IPC pipe EOF to report `ExecutionLimitError("max_memory_bytes")` only when exit code indicates SIGKILL/OOM (`-9` or `137`) under an active hard limit, and `PyChefError` otherwise.
  - Added support for passing custom `OperationRegistry` instances across worker processes.
- **Flow Control Resource Guards**:
  - Early delimiter and regex pattern size validation in `Fork` and `Subsection` against `policy.max_input_bytes`.
  - Enforced recursion depth and branch limits on nested forks.
- **Unified Execution Policies & Safety Profiles**:
  - `ExecutionPolicy.safe()` (default): Conservative budgets (512 MiB memory, 16 MiB input, 64 MiB output, 10k steps/branches, 30s deadline) and network disabled.
  - `ExecutionPolicy.untrusted()`: Stricter sandboxing for untrusted data.
  - `ExecutionPolicy.unrestricted()`: All resource caps lifted (`None`) and unrestricted network access.
  - `ExecutionPolicy.permissive()`: Legacy profile preserving backwards-compatibility with open public network.
  - Explicit `None` disables any numeric budget without falling back to internal defaults.
  - Fixed `ExecutionPolicy.with_overrides()` to reliably preserve `None` values and properly synchronize with `NetworkPolicy`.
- **Granular Network Control & SSRF Protection**:
  - `NetworkPolicy` as the single source of truth with modes `disabled`, `public_only`, and `unrestricted`.
  - Strict host normalization (case-folding, trailing-dot removal, IDNA/Punycode encoding).
  - Strict deny-over-allow precedence across hosts and subnets.
  - Configurable `allowed_hosts`, `denied_hosts`, `allowed_subnets`, `denied_subnets`, `allowed_ports`, `denied_ports`, `allowed_schemes`, `timeout_seconds`, and `max_redirects`.
  - DNS pinning directly into socket connections to prevent DNS rebinding attacks.
  - Explicit bypass of environment proxies (`HTTP_PROXY`) to enforce destination checks.
- **Worker Process Isolation & Platform Awareness**:
  - `IsolatedWorker` and `bake_isolated()` executing recipes in isolated subprocesses using `spawn` context.
  - Explicit distinction between cooperative in-process data budgets and OS-level address space limits (`hard_memory_limit_bytes`).
  - Added `IsolatedWorker.is_hard_memory_limit_supported()`; unsupported platforms fail honestly with actionable guidance.
  - Zombie-free process reaping lifecycle and clean serialization of unpicklable child exceptions.
- **Pipeline Execution Consistency & Bounded Tracing**:
  - Unified `Pipeline.trace()` under `active_policy` and `ExecutionContext` identically to `transform()`.
  - Bounded trace buffers honoring `policy.max_trace_bytes` and added preview truncation (`max_preview_bytes`).
- **Resource Hardening & Error Sanitization**:
  - Included merge delimiter byte length in `Fork` accumulated output size tracking.
  - Early output size checking on `Subsection` prefix, parts, and suffix.
  - Sanitized `OperationError` exception strings against secret leakage (keys, passphrases, IVs, salts) with root-cause preservation via `__cause__`.
- **Registry & Spec Isolation**:
  - Enabled lazy loading into separate `OperationRegistry` instances with full override isolation from the global registry.
- **On-Demand Lazy Loading**:
  - Registry lazily imports individual operation modules only when requested, drastically improving initial import times and reducing memory footprints.
  - `by_operation` module supports dynamic `__getattr__` and `load_all()`.
- **Introspection & Metadata API**:
  - Structured `OperationSpec` and `OperationArgSpec` dataclasses.
  - `pychef.get_operation_spec(name)`, `pychef.list_operation_specs()`, `registry.spec(name)`, and `registry.specs()`.
  - Built-in `_data/cyberchef_operations.json` packaged with wheel distributions.
- **Pipeline Streaming**:
  - `Pipeline.iter_transform()` for generator-based streaming across large sequences with shared execution context.
- **Performance Fast-Paths**:
  - Standard-rounds fast path for `SHA1` and `SHA2` (224, 256, 384, 512) yielding up to 3,800x speedups while preserving bit-exact custom-round fallbacks.

### Changed

- Default execution policy across `bake()` and `Chef()` changed to `ExecutionPolicy.safe()` (network disabled by default).
- Structured error information on all `PyChefError` instances (`error_code`, `step_index`, `branch_path`, `execution_id`, `to_dict()`).
- Error unpickling support (`__reduce__`) across processes for `OperationError`, `ExecutionLimitError`, and `ExecutionTimeoutError`.

### Fixed

- **Windows time zones**: `Translate DateTime Format` and the other time zone operations
  failed on Windows with `ZoneInfoNotFoundError` because Windows has no IANA database.
  `tzdata` is now a Windows-only runtime dependency (`tzdata; platform_system == 'Windows'`).
  A missing zone now reports its identifier (and a `tzdata` hint when no database exists)
  instead of `[REDACTED]`; the sanitizer is otherwise unchanged.
- **One execution, one context**: `Recipe.execute`, `bake`, `Chef`, `Pipeline` (including
  `iter_transform`), and `pychef.ops` now share the running `ExecutionContext` when called
  inside an execution (for example from `Pipeline.apply`): step budget, deadline, trace,
  execution id, and branch path continue instead of restarting. A different
  `ExecutionPolicy` inside a running execution is rejected with `ValueError` (no silent
  privilege escalation). Independent top-level calls keep independent contexts.
- Hash helpers (`pychef.ops.md5/sha1/sha256/sha512/digest`) now charge a step and apply the
  input limit, output limit, deadline, and trace like every other direct operation.
- `IsolatedWorker`: malformed or undecodable result messages raise `PyChefError`; the reader
  cleanup after a timeout is bounded (1 s) instead of 5 s and parks a reader thread that
  cannot be interrupted rather than closing its handle.
- `Pipeline.concat()` branches now run inside the caller's single `ExecutionContext`.
  Previously each branch created a fresh safe-default context, so step, branch and
  deadline budgets were reset and an `unrestricted` outer policy was silently replaced by
  safe defaults inside branches. Branch steps are now traced with their `branch_path`.
- HTTP redirect responses are no longer drained with an unbounded `read()`; the body is
  discarded by closing the connection (no hidden size limit; `max_response_bytes=None`
  keeps its meaning for the final response).
- `IsolatedWorker` deadlines now also cover the receive of a partially written IPC message
  (previously `poll()` followed by a blocking `recv()` could wait forever); the reader is
  stopped and the child terminated at the deadline.
- `import pychef` no longer imports the AES implementation (loaded on first use).

### Known limitations

- Registered operations are not all byte-for-byte CyberChef-identical for every option; see
  `COMPATIBILITY.md` and the compatibility page for the documented boundaries.
- `ExecutionPolicy` limits are cooperative (checked between steps); only `IsolatedWorker` on
  Linux can enforce a hard memory limit. A stalled operation inside a single step is not
  interrupted in-process.
- `Pipeline.apply` callables are trusted Python code and are not sandboxed.
- `IsolatedWorker` deadlines can overshoot by up to ~3 s (termination grace and reader
  cleanup); a descendant process that keeps the result pipe open can park one daemon thread.
- Worker behaviour is platform dependent (spawn start method everywhere; hard limits Linux-only).

## [0.1.1] - 2026-08-01

### Fixed

- Aligned Charcode, HTML Entity, Base85, Float, Punycode, and general radix
  conversion arguments and outputs with the pinned CyberChef implementation.
- Reworked Template JSON rendering, fuzzy matching, frequency distribution,
  chart parsing, smart-character escaping, string escaping, random-generator
  formats, and offset highlighting.
- Added validation limits for De Bruijn and Lorem Ipsum generators and hardened
  chart and template output escaping.

### Documentation

- Added the Read the Docs URL to package metadata and the project README so the
  next distribution published to PyPI links directly to the hosted manual.

## [0.1.0] - 2026-08-01

### Added

- The `cyberchef-py` distribution with the `pychef` import package.
- Pure-Python implementations for all 502 CyberChef operation names.
- CyberChef-compatible recipes with flow-control support.
- Immutable transformation pipelines with composition, branching, tracing,
  and output concatenation.
- CTF helpers for packing, endianness, XOR, hashing, AES modes, hexdumps, and
  de Bruijn patterns.
- Structured Ethernet, IP, TCP, UDP, DNS, PCAP, and PCAPNG parsing.
- Type information, pytest coverage, Ruff linting, and ty type checking.

[Unreleased]: https://github.com/MichaelWeissDEV/pychef/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/MichaelWeissDEV/pychef/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/MichaelWeissDEV/pychef/releases/tag/v0.1.0
