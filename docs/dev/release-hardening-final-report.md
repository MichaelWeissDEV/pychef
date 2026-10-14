# PyChef Release Hardening – Final Engineering Report

**Date:** 2026-10-14  
**Project:** PyChef / cyberchef-py  
**Baseline Commit:** `07d4a6f592264f6680b1baa6d66104bd8340502b`  
**Target State:** Release Candidate (Hardened, Validated, Fully Tested)  
**Status:** All Release Gates Passed (1,140 tests passing, 85.12% coverage, 0 lint/format/type issues, 100% build verification)

---

## 1. Executive Summary

In this development cycle, PyChef underwent end-to-end security hardening, resource management stabilization, configuration contract completion, and test-driven regression coverage. All 13 development phases (Phases 0 through 12) have been successfully implemented and verified locally without regressions.

The resulting codebase fulfills all operational safety criteria for untrusted data transformation, network policy enforcement, process isolation, and public API predictability.

---

## 2. Before vs. After Comparison

| Metric / Dimension | Baseline (`07d4a6f`) | Release Candidate |
|---|---|---|
| **Passing Tests** | 1,089 | **1,140** (+51 new tests) |
| **Total Test Files** | 77 | **80** (added `test_error_confidentiality.py`, `test_pipeline_tracing.py`) |
| **Test Coverage** | 85.04% | **85.12%** (exceeds 75% requirement) |
| **Ruff Check / Format** | Clean | Clean (0 issues) |
| **Static Typing (`ty check`)** | Clean | Clean (0 diagnostics) |
| **Sphinx Documentation** | Passed | Passed (`-W --keep-going` clean) |
| **Wheel & Sdist Distribution** | Passed | Passed (twine check + check-wheel-contents OK) |
| **Smoke Tests (Isolated)** | Passed | Passed (wheel & tar.gz) |
| **Import Time** | ~48 ms | **46.04 ms** (< 50 ms budget) |
| **SHA-256 (1 MB)** | ~1,100 MB/s | **1,121.8 MB/s** |
| **Base64 (1 MB)** | ~225 MB/s | **230.0 MB/s** |
| **IsolatedWorker Overhead** | ~55 ms | **50.79 ms** |

---

## 3. Security Vulnerabilities Mitigated & Hardening Implemented

### 3.1 HTTP Redirect Credential Leak Prevention (Phase 1)
- **Vulnerability:** Standard `urllib.request.HTTPRedirectHandler` copies all headers (including `Authorization` and `Cookie`) to redirected requests indiscriminately, even when following cross-origin redirects (`http://example.com` -> `http://evil.com`).
- **Remediation:** Implemented `_get_origin()` with strict scheme, port (defaulting 80/443), and IDNA/Punycode host normalization. Enhanced `_SafeRedirectHandler` to inspect origins and delete sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Cookie2`, and user-defined `sensitive_headers`) from both `headers` and `unredirected_hdrs` on origin transitions.
- **Verification:** Verified via multi-server loopback test matrix covering same-origin retention, cross-origin stripping, custom sensitive headers, and redirect chains.

### 3.2 Enhanced SSRF Defense & DNS-Pinning (Phase 2)
- **Vulnerability:** Hostnames matching `allowed_subnets` were prematurely rejected when `mode="disabled"` before DNS resolution could take place. IPv6-mapped IPv4 addresses (`::ffff:127.0.0.1`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) bypassed IPv4 subnet checks. Mixed DNS answers containing forbidden IPs were not guaranteed to block connections.
- **Remediation:**
  - Introduced `PolicyDecision` enum (`ALLOW`, `DENY`, `NEEDS_RESOLUTION`) and `evaluate_pre_resolution()` to safely schedule DNS resolution only when needed for subnet matching.
  - Added recursive IPv6 mapped unwrapping in `check_destination()` ensuring IPv4 subnets and deny lists are enforced across all representations.
  - Hardened DNS resolution validation to reject DNS responses if any returned IP address violates the policy.

### 3.3 Unbounded Redirects & Network Timeouts (Phase 3)
- **Vulnerability:** Configuring `max_redirects=None` caused a `TypeError` in Python's standard library `urllib` due to `len(visited) >= None`.
- **Remediation:** Overrode `http_error_302` in `_SafeRedirectHandler` to safely handle `max_redirects=None` (unrestricted redirects) while maintaining total redirect count tracking and enforcing positive numeric limits and `max_redirects=0`.

### 3.4 ExecutionPolicy Configuration Contract (Phase 4)
- **Vulnerability:** Explicitly setting `max_memory_bytes=None` or `allow_network=None` via `with_overrides()` was either overridden by truthiness fallbacks (`limit or DEFAULT`) or raised `TypeError`.
- **Remediation:** Introduced `_UNSET` sentinel to distinguish omitted parameters from explicit `None`. Added strict parameter validation (rejecting negative numbers and booleans for numeric fields) adhering to "unrestricted means unrestricted".

### 3.5 Error Handling & Data Confidentiality (Phase 5)
- **Vulnerability:** Exception messages could inadvertently leak raw input data, keys, or passwords.
- **Remediation:**
  - Enhanced `_sanitize_error_message()` across `Recipe`, `Pipeline`, and `Chef` to recursively inspect arguments, input values, and intermediate payloads.
  - Added regex scrubbing for Bearer tokens, cookies, passwords, and API keys.
  - Added `safe_message` property and field to `to_dict()` on `PyChefError`.
  - Added test suite with dummy credentials (`TEST_SECRET_INPUT_12345`, `TEST_SECRET_PASSWORD_12345`, `TEST_SECRET_API_KEY_12345`, `TEST_SECRET_SESSION_COOKIE`) verifying that `exc.message`, `exc.safe_message`, `str(exc)`, `repr(exc)`, and `exc.to_dict()` never contain unmasked secrets.

### 3.6 Cycle-Safe Pipeline Tracing & Buffer Bounds (Phase 6)
- **Vulnerability:** Circular container references caused `RecursionError` during trace size measurement. Stored preview truncation did not respect multi-byte UTF-8 boundaries. Trace memory accounting charged full input size rather than retained preview size.
- **Remediation:**
  - Implemented cycle-safe object ID tracking in `_measure_trace_size()`.
  - Handled UTF-8 preview slicing with `decode("utf-8", "ignore")` to prevent split multi-byte characters.
  - Charged actually stored preview bytes against `policy.max_trace_bytes`.
  - Added lazy streaming test ensuring `Pipeline.iter_transform()` does not eagerly consume generators.

### 3.7 IsolatedWorker Hardening & Concurrency Protection (Phase 7)
- **Vulnerability:** Concurrently invoking `run()` on the same `IsolatedWorker` instance caused race conditions on IPC pipes and process handles. Process creation failures leaked pipes and left dead process references. Unexpected child process termination was indiscriminately reported as memory limit errors. Custom operation registries could not be executed inside worker processes.
- **Remediation:**
  - Added non-blocking thread lock to `IsolatedWorker.run()` (Model A) raising clear `RuntimeError` on concurrent misuse.
  - Enclosed process start in `try/finally` to safely close pipes, reap processes, and reset `_current_process`.
  - Differentiated unexpected EOF: only exit codes in `(-9, 137)` under an active hard limit are reported as `ExecutionLimitError("max_memory_bytes")`; otherwise reported as `PyChefError("Worker process terminated unexpectedly with exit code {exitcode}")`.
  - Added `OperationRegistry.__getstate__` and `__setstate__` and passed custom registries into worker processes.

### 3.8 Flow Control Resource Guards (Phase 8)
- **Vulnerability:** Maliciously large split delimiters (e.g. 10 MB) or regexes could trigger excessive allocations before input checks fired.
- **Remediation:** Added early `max_input_bytes` checks for delimiters in `Fork` and patterns in `Subsection`. Verified recursion depth, branch count limits, infinite jump loops, and nonexistent label tolerance.

---

## 4. Release Gate Verification Summary

| Gate Check | Command | Status | Output Details |
|---|---|---|---|
| **Test Suite** | `uv run pytest` | **PASS** | 1,140 passed in 51.19s, 85.12% coverage |
| **Linting** | `uv run ruff check .` | **PASS** | All checks passed (0 errors) |
| **Formatting** | `uv run ruff format --check .` | **PASS** | 681 files already formatted |
| **Type Checking** | `uv run ty check` | **PASS** | All checks passed (0 diagnostics) |
| **Package Build** | `uv build --clear` | **PASS** | `cyberchef_py-0.1.1.tar.gz`, `cyberchef_py-0.1.1-py3-none-any.whl` |
| **Metadata Check** | `uv run twine check dist/*` | **PASS** | Both wheel and sdist PASSED |
| **Wheel Contents** | `uv run check-wheel-contents dist/*.whl` | **PASS** | OK |
| **Documentation** | `uv run --group docs sphinx-build -W --keep-going -b html docs docs/_build/html` | **PASS** | Build succeeded, 0 warnings |
| **Isolated Smoke Tests** | `uv run --isolated --no-project --with dist/* tests/smoke_test.py` | **PASS** | Both wheel and sdist smoke tests passed |

---

## 5. Recommendations for Future Releases

1. **Linux cgroup v2 Integration**: Explore optional cgroup v2 controller support for systems where `RLIMIT_AS`/`RLIMIT_DATA` is limited by allocator behavior.
2. **Subprocess Worker Pooling**: For ultra-high throughput environments executing thousands of micro-recipes, provide an optional pre-warmed worker pool to amortize the ~50 ms process spawn overhead.
3. **HTTP/2 & HTTP/3 Verification**: When extending the networking layer beyond Python's built-in `urllib.request`, ensure identical origin normalization, sensitive header stripping, and DNS pinning semantics are preserved.
