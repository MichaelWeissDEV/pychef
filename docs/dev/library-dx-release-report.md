# Library DX and release-readiness report

> **Status note (superseded in part).** This report was written before commit `02eb781`,
> which contains this work. The current state, the Windows CI failure, and the later
> context/Windows fixes are in `pychef-0.2.0-final-readiness.md`. Statements below that
> say "uncommitted", "no runtime dependencies", or "pending CI" describe the earlier state.

Prepared for review; at writing time nothing was committed, pushed, tagged, or published.

## 1-2. Commits

* Base commit: `9d3906398c9bb3e0edcbb35d2596c156e636633d` (package version `0.1.1`).
* Work was subsequently committed as `02eb781`.

## 3-5. Public API design, new imports, direct operations

* Four documented entry points on **one** engine: `pychef.ops` (direct), `bake`/`Recipe`
  (recipes), `Pipeline` (fluent), `Chef`/`ExecutionPolicy`/`IsolatedWorker` (configured).
* New `pychef.ops` (also reachable as `pychef.ops` via lazy attribute): `from_hex`,
  `to_hex`, `from_base64`, `to_base64`, `from_base32`, `to_base32`, `url_encode`,
  `url_decode`, `html_encode`, `html_decode`, `rot13`, `reverse`, `xor`, `gzip_compress`,
  `gzip_decompress`, `md5`, `sha1`, `sha256`, `sha512`, `digest`, `run_operation`,
  `using_policy`. No `*args`/`**kwargs`; options are keyword-only and named.
* Every helper runs through `Recipe.execute` with an `ExecutionContext`. The effective
  policy is: explicit `policy=` (`run_operation`) > the innermost active policy (a
  `using_policy()` block or a running `bake`/`Pipeline`/`Chef`; both are scoped `ContextVar`s,
  no global state) > `safe()`.
  Network operations are therefore denied exactly as in `bake()`.
* Design decisions you may want to revisit:
  * `to_hex` defaults to no delimiter (matches `Pipeline.to_hex`), whereas a bare
    `To Hex` recipe step defaults to `"Space"`. Documented.
  * `rot13`/`reverse` return the input's type (`str` -> `str`); `reverse` rejects
    byte-wise reversal of `str`.
  * `ops.xor` rejects an empty key (the `XOR` operation silently substitutes a zero byte).
  * Hash helpers wrap the existing `ctf` functions (same hex format, no second
    implementation) and add the policy's input limit.
* Not done deliberately: no 502 generated wrappers, no new top-level names.

## 6. Recipe and Pipeline

* `Recipe`: `__repr__`, `__len__`, `to_config()`, `to_json()`, `from_json()`.
* `Pipeline.concat()` branches share the caller's single `ExecutionContext`
  (see fixes below). `Pipeline.trace()` and `transform()` now share one `_run` loop
  (removes a ~60-line duplicate).
* Docs state: `apply()` is trusted code, not a sandbox; `iter_transform` is a generator,
  `transform_many` materializes; both share one budget/deadline for the whole batch.

### Phase 1 fixes (each with a regression test that fails on the base commit)

Base-commit behaviour: the redirect and branch tests fail on `9d39063`. The worker tests
cannot run there (the helper does not exist and the end-to-end case would hang), so the
partial-frame hang was confirmed by reasoning plus a direct reproduction with
`Connection.poll()` returning true on a partial frame, not by a failing base test.

| Issue | Result | Test |
|---|---|---|
| Redirect body drained by `fp.read()` | Confirmed unbounded/slow-body hang. Body is no longer read; the connection is closed. No hidden limit (`max_response_bytes=None` still unlimited for the final response). | `test_redirect_body_is_not_drained[1024/None]` (local server that never finishes the redirect body) |
| `poll()`+`recv()` in worker | Confirmed: `poll` is true for a partial frame, `recv` then blocks forever. Receive now runs in a reader thread bounded by the deadline; at the deadline the child is terminated and the thread joined before the pipe is closed. | `test_recv_before_deadline_*`, end-to-end `test_isolated_worker_deadline_covers_partial_ipc_message` (real spawned child writing a partial frame) |
| Branch contexts | Confirmed: each branch created a fresh safe context (budgets reset; `unrestricted` outer policy lost). | `test_concat_branches_share_*`, `test_branches_keep_outer_policy_object`, `test_branches_keep_deadline_and_trace` |

Existing worker tests (small/large results, EOF, unpicklable errors, cleanup) still pass.
New: a child sending an undecodable frame, and a child aborting with `os._exit(3)`, with and
without a deadline. The first leaked a raw `ValueError: unsupported pickle protocol`; it is
now a `PyChefError("... unreadable result message")` (malformed payloads likewise), pipe
`OSError` is treated as an unexpected child exit, and the process is reaped in all cases.

Also: `IsolatedWorker` timeouts for a *slow* child are unchanged; streams (`iter_transform`)
share one budget and one wall-clock deadline that includes consumer time. This is existing
behaviour, now documented and tested; use `ExecutionPolicy(max_steps=None,
cooperative_deadline_seconds=None)` for long streams (the streaming example does).

## 7. Typing

* `py.typed` ships in the wheel (asserted). Overloads: `digest` (`output` -> `str`/`bytes`),
  `rot13`, `reverse` (input type -> output type). `Literal` aliases for option values.
* `tests/typing_examples/ops_usage.txt` is checked with `ty` against `src/` (pytest) and,
  via `tests/check_wheel_typing.py`, **against the installed wheel in a fresh venv**
  (CI `quality` job). Exactly the two intentional misuse lines are flagged.
* `Pipeline` was not made generic (stages carry arbitrary objects); not worth the churn.

## 8. Import comparison (Apple M4 Max, macOS 25.4 arm64, CPython 3.13.5)

Method: `docs/_scripts/benchmark_api.py`; fresh `python -I` per sample, median of 15 runs;
per-call numbers are medians of 15 x 2000 calls after a 100-call warm-up.
Baseline measured from a separate `git worktree` of `9d39063`.

| Metric | Base `9d39063` | Current |
|---|---|---|
| `import pychef` | 24.8 ms, 18 modules, 32.1 MB RSS | 22.4 ms, 13 modules, 32.0 MB |
| `from pychef.ops import from_hex` | n/a | 22.6 ms, 20 modules, 32.0 MB |
| import + first `bake` | 27.3 ms | 24.9 ms |
| `bake` two steps | 14.8 us | 15.0 us |
| `Recipe(...)` | 0.7 us | 0.7 us |
| `Pipeline()` two steps / reused call | 1.5 us / 12.6 us | 1.6 us / 12.8 us |
| `ops.to_base64(ops.from_hex(..))` | n/a | 21.6 us (builds a Recipe + context per call) |
| `bake_isolated` (spawn) | 48.4 ms | 45.0 ms |

Differences of a few percent are within noise; the only structural change is the
lazy AES import (-5 modules). `pychef.ops` adds no operation modules until used.
Single-run numbers on one machine; do not generalise.

## 9. Packaging

* Version bumped to **0.2.0** (`pyproject.toml`, `uv.lock` refreshed, `uv lock --check` ok).
* `uv build --no-sources`, `twine check --strict`, `check-wheel-contents`: pass.
  The wheel contains `pychef/ops/*`, `py.typed`, LICENSE, NOTICE, THIRD_PARTY_LICENSES;
  no tests or caches. No runtime dependencies (asserted in the smoke test).
* The old local `dist/` (0.1.1 artifacts, untracked) was replaced by the 0.2.0 build.
* Workflows: environment URLs fixed to `cyberchef-py`; publish verifies tag == version
  and that exactly the two expected artifacts exist; test-publish checks the same against
  the package version; both run the wheel typing check. Not verified: Trusted Publisher
  settings on PyPI/TestPyPI (outside the repository).

## 10. Installation smoke tests

Wheel and sdist were installed in isolated uv environments (from `/tmp`, repository not
importable) and ran the extended `tests/smoke_test.py` (version, no deps, `py.typed`,
registry of 502, recipe/pipeline/direct ops/CTF/spec, network denied): both pass.
`pip install cyberchef-py` from PyPI would install 0.1.1 until a release exists; it was
not tested against the new code (by design). `uv pip check` runs inside
`tests/check_wheel_typing.py` against the installed wheel; plain `pip` was not used.

## 11-12. Documentation and tested examples

* New: `choosing-an-api`, `direct-operations`, `cookbook`, `development`,
  `api/ops`, `api/execution`, `api/worker`; reworked `getting-started`, `index`;
  additions to `pipelines` and `compatibility`; README rewritten and shortened.
  `sphinx-build -W --keep-going` passes (docs extras were synced for it).
* 13 example scripts in `examples/`, all run by `tests/test_examples.py` in a fresh
  interpreter. 52 `>>>` doctests in four doc pages run by `tests/test_docs_snippets.py`.
* Not done: the audit calls out that the generated per-operation pages were only
  checked for consistency (`generate_operation_docs.py --check`), not re-audited for
  every default/example; no cross-links from operation pages to `pychef.ops` helpers;
  no versioned (stable/latest) Read the Docs setup beyond the notes in `RELEASING.md`
  (needs the RTD project); mobile layout/code-block rendering was not inspected.

## 13. Platform compatibility

CI now has `macos-latest` and `windows-latest` jobs (Python 3.13) next to the Linux
matrix 3.10-3.14. **They have not run.** Locally only macOS/arm64 CPython 3.13 was
exercised (full suite) plus a subset on Python 3.10 (158 tests of the new API, examples, docs, and tracing passed on 3.10). Known platform
notes: hard memory limits are Linux-only (tests skip elsewhere); two new IPC tests that
write raw frames are skipped on Windows; existing tests that may assume POSIX behaviour
(paths, signals) are unverified on Windows. Do not treat Linux/macOS results as proof
of Windows support.

## 14. Tests and coverage

`uv run pytest`: **1209 passed** (base commit: 1140 collected), total branch coverage
85.4 % (gate 75 %). 69 net new tests, all behavioural; the 93 baseline-symbol checks
are one set-difference assertion rather than 93 parametrized cases. `ruff format`,
`ruff check` and `ty check` are clean.

## 15. Open problems

* Windows/macOS CI untested; RTD versioning not configured here.
* `Pipeline.apply` callables are not interruptible; the deadline is checked between stages.
* `ops` helpers rebuild a `Recipe` and context per call (~10 us/op); fine for typical use,
  not for tight inner loops (use bytes-level stdlib or a `Pipeline`).
* Pre-existing duplicate XOR logic (`ctf.xor_bytes` vs `maths._bitwise`) remains.
* `IsolatedWorker` reader-thread approach leaves one short-lived thread per call;
  at timeout it is joined (up to 5 s) after the child is killed.

## 16. Breaking changes

None intended. Behavior changes: `Pipeline.concat` branches now honour the outer policy
(previously each branch used fresh safe defaults); `Pipeline.concat` branches count toward
`max_branches`/`max_recursion_depth` (a deeply nested concat can now hit the recursion limit
of 8); `import pychef` no longer imports `pychef.operations.aes` as a side effect (code
that relied on `pychef.operations` being loaded after `import pychef` still works through the
lazy attribute).

## 17. Version recommendation

Read-only index check (2026-10-14): PyPI lists only `0.1.0` and `0.1.1` for `cyberchef-py`
(`/pypi/cyberchef-py/0.2.0/json` returns 404); TestPyPI has no such project yet. Both publish
workflows now fail early if the version already exists on their index.

**0.2.0**: new public API (`pychef.ops`, `Recipe` serialization) plus fixes, pre-1.0 so the
branch-policy change is acceptable as a minor bump. The CHANGELOG `[Unreleased]` section
already contains the changes; it still has to be renamed to `[0.2.0] - <date>` at release time.

## 18. Release readiness

Release-candidate ready **pending**: review and commit of the working tree, a green CI
run on all three platforms, TestPyPI installation, and explicit approval to publish.
No known P0 defects in the local checks.
