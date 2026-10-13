# Changelog

All notable changes to this project are documented here. Releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
