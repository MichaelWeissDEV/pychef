# PyChef 0.2.0 – final readiness report

## A. Repository

* Last public commit examined: `02eb7817` (also local `HEAD` and `origin/main` at start;
  the working tree was clean, branch `main`). No local divergence from GitHub existed.
* Current state: all changes below are **uncommitted** in the working tree on top of
  `02eb781`. Nothing was pushed, tagged, or published.
* Version: `0.2.0` (`pyproject.toml`, `uv.lock`). Last published: 0.1.1.
* Baseline CI (run 38607915563): Linux 3.10-3.14, macOS 3.13, quality and Sphinx green;
  **Windows 3.13 red**. This report cannot show a green CI for the new changes: they have
  not been pushed.

## B. Fixed defects

| Defect | Cause | Fix | Regression test |
|---|---|---|---|
| Windows `test_translate_datetime_format_official_vectors` fails (`No time zone found with key US/Eastern`) | `zoneinfo` needs an IANA database; Windows has none and `tzdata` was not a dependency | Windows-only runtime dependency `tzdata; platform_system == 'Windows'` in `pyproject.toml` (lock updated, resolves to `sys_platform == 'win32'`); smoke test imports `US/Eastern` on Windows | `tests/test_timezones.py`, `tests/test_datetime.py` |
| Zone errors read `unknown timezone: [REDACTED]` | The sanitizer redacts every string option >= 4 chars | `Recipe._sanitize_error_message` keeps only an exact, strictly shaped zone identifier (`[A-Za-z0-9_+\-/]{1,64}`) in an `unknown timezone:` message; added `tzdata` hint when no database exists. The sanitizer is otherwise untouched | `test_unknown_zone_names_the_identifier`, `test_missing_database_gives_actionable_hint`, `test_zone_identifier_is_not_a_blanket_sanitizer_exemption` |
| Nested calls started a new context (`Pipeline().apply(to_base64)` with `max_steps=1` succeeded) | `Recipe.execute`, `Chef`, `Pipeline` and `pychef.ops` each created an `ExecutionContext`; only the policy was inherited | New scoped `current_context()`/`active_context()`/`resolve_context()` in `execution.py` (ContextVar, tokens reset on exit); all entry points adopt the running context. Different policy inside a running execution -> `ValueError` | `tests/test_execution_context_sharing.py` (17 tests) |
| Hash helpers skipped steps/output/deadline | `_digest(guard_input(...))` only checked input size | `execute_direct()` in `ops/_engine.py` (1 step, input/output limits, permission check, deadline, trace); `guard_input` removed; hashlib code unchanged | `tests/test_hash_limits.py` |
| Worker cleanup waited `join(5.0)` after a timeout | Fixed, unexplained cleanup bound | The kill closes the pipe's write end, so the blocked reader ends with EOF immediately; bound reduced to a documented 1 s. A reader that cannot end (descendant holds the handle) is parked as a daemon thread and its connection is *not* closed (avoids fd reuse) | `test_worker_timeout_returns_promptly_and_cleans_up`, `test_blocked_reader_is_parked_not_waited_for`, `test_worker_without_deadline_returns_results` |

The earlier fixes (redirect body, partial-frame `recv`, branch contexts, malformed frames) remain
and are covered by `tests/test_phase1_regressions.py`.

## C. Execution engine

* One execution = one `ExecutionContext`: steps, branches, depth, deadline, trace, execution
  id and branch path are shared by `bake`, `Chef`, `Pipeline` (incl. `concat` and
  `iter_transform`) and `pychef.ops`, including nested hash helpers (tested individually).
* Top level: new context under `safe()` (or `using_policy`); independent top-level calls have
  independent budgets. Threads start clean; asyncio tasks inherit the same context (documented).
* `using_policy` inside a running execution with a different policy is rejected; at the
  top level it is a host decision. Explicit `None` limits are inherited as chosen.
* Design choice: reject instead of intersecting policies (simplest, no hidden escalation).
* Not changed: `IsolatedWorker` runs a separate process (independent context, documented).

## D. Direct operations

* Same 22 exports, signatures unchanged. Behaviour changes: nested joining as above; hashes
  now charge one step (`max_steps=0` blocks them).
* Typing: the `ty` check of the example against both `src` and the installed wheel passes.
* Performance: unchanged design (one Recipe+context per call, ~10 us/op, see the earlier
  report); the nested path reuses the context and is cheaper than a fresh one. No new
  benchmark was run for this round.

## E. Platforms

* Executed locally: macOS 26 arm64, CPython 3.13.5; subset on 3.10 in the previous round.
* **Not executed here:** Windows and Linux 3.10-3.14 full matrix. The Windows fix is verified
  only by reasoning and by simulating a missing database (monkeypatch); the real proof is the
  Windows CI job, which must run without skipping the formerly failing test (none was skipped).
* Windows-sensitive new tests: raw-frame tests are skipped on `win32` (POSIX `Connection`
  framing; justified, equivalent behaviour is covered by the platform-neutral silent-child test).

## F. Tests and gates (local, macOS)

* `uv run pytest`: **1257 passed**, coverage **85.48 %** (gate 75 %). Previous commit: 1209.
* `ruff format --check`, `ruff check`, `ty check`: clean. `uv lock --check`,
  `validate-pyproject`: ok.
* `uv build --no-sources`: wheel + sdist; `twine check --strict` and `check-wheel-contents`
  pass; wheel has no `tests/` files and `Requires-Dist: tzdata; platform_system == 'Windows'`.
* Wheel and sdist smoke tests in isolated environments pass; installed-wheel type check and
  `uv pip check` pass. All `examples/*.py` run; doctests in the four doc pages pass.
* Sphinx `-W --keep-going` (full clean build, exit 0) and `generate_operation_docs --check`: pass.

## G. Release

* Changelog: `[Unreleased]` documents the 0.2.0 candidate with Added/Changed/Fixed/Known
  limitations; it still needs renaming to `[0.2.0] - <date>` at release time.
* Docs: new context/policy/host-boundary sections, installation note (PyPI vs development),
  dependency statements corrected (tzdata on Windows).
* Open: Windows CI result; Read the Docs stable/latest setup (needs the RTD project);
  mobile layout of docs not inspected; the existing `Known limitations` remain.
* No tag, no TestPyPI/PyPI publication was made.

## H. Decision

**NOT READY FOR RELEASE CANDIDATE** – formally, because the Definition of Done requires a
fully green GitHub CI (including Windows) and these changes have not been pushed or run
there. All local checks are green and no known P0 defect remains; once the CI matrix passes
on a commit containing these changes the decision flips to READY FOR RELEASE CANDIDATE.
