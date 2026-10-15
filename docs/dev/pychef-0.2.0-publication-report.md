# PyChef 0.2.0 publication report

Status as of 2026-10-15. Statuses are set only where evidence exists.

| Status | State |
|---|---|
| SOURCE READY | yes |
| DOCUMENTATION BUILT | yes (local `sphinx -W`, CI Sphinx job) |
| CI PASSED | yes, all 9 jobs on the release commit |
| TAG RECREATED | yes |
| GITHUB RELEASE PUBLISHED | **no** (needs a GitHub token / manual action) |
| PYPI 0.2.0 PUBLISHED | **no** (triggered by the GitHub release) |
| PUBLIC INSTALLATION VERIFIED | no (nothing published yet) |
| READ THE DOCS DEPLOYED | **not verified**; `/en/v0.2.0/` returned 404 before retagging |
| RELEASE COMPLETE | **no** |

## Repository

* Release commit: `b0d67aa46c1366edd2eacbe578e2345b8802b2ee`.
* Old tag object `6363bac31135acfc302342de0353084cd837da06` -> commit `0c0fc57388c66fe60380059969b77f88a1592d89`
  (never published to PyPI or as a GitHub release; PyPI listed only 0.1.0/0.1.1).
* New tag object `56b16fe89ba89e8d5626289ca0e54c1edb03dfcf` -> commit `b0d67aa46c1366edd2eacbe578e2345b8802b2ee`
  (verified with `git ls-remote` and `git rev-parse 'refs/tags/v0.2.0^{commit}'`).
* Documentation-only commits after the tag (this report) go to `main`; the tag is not moved again.

## Defects and regression review

* **macOS failure** (`test_isolated_worker_timeout_termination`): the test passed
  `"argon2i"` as the Argon2 hash length and relied on a 20 ms deadline firing before
  argument validation. Replaced by a blocking operation in a picklable custom registry
  (deadline 1 s), asserting `ExecutionTimeoutError`, process reaping, no live reader threads,
  and worker reuse; plus repeated-timeout, invalid-Argon2 (`OperationError`) and valid-Argon2
  tests. Run 20 times locally without failure; no skip/xfail.
* **Parked reader lifecycle**: confirmed that `_PARKED_READERS` entries (thread + connection)
  were only pruned when another reader was parked. Now pruned (and connections closed) at every
  `IsolatedWorker.run`. A reader whose handle is held by a descendant process still cannot be
  interrupted (accepted limitation, documented).
* Previously fixed items re-checked by the suite: shared `ExecutionContext` (steps, input/output,
  deadline, nesting, hash helpers, context restore, policy conflicts), safe network defaults,
  explicit `None` limits, Windows `tzdata`.
* No new release-blocking defect found.

## Quality evidence

* Local: 1263 tests passed, coverage 85.50 %; ruff, ty, validate-pyproject clean; wheel and sdist
  build (`cyberchef_py-0.2.0-py3-none-any.whl`, `cyberchef_py-0.2.0.tar.gz`), `twine --strict` and
  `check-wheel-contents` pass; isolated wheel/sdist smoke tests and installed-wheel typing pass.
* CI run for the release commit: https://github.com/MichaelWeissDEV/pychef/actions/runs/38661561570 --
  Ubuntu 3.10-3.14, Windows 3.13, macOS 3.13, Quality and distributions, Sphinx: all success.
  (Per-platform test totals are in the job logs, which need repository admin rights to download.)
* Operation reference generator is deterministic (`--check` clean, second run no diff).

## Remaining steps (need account access)

1. **GitHub release**: tag `v0.2.0`, title "PyChef 0.2.0", not draft, not prerelease, body from
   `docs/dev/release-notes-0.2.0.md`. Publishing it starts `publish.yml` (environment `pypi`,
   Trusted Publisher: owner MichaelWeissDEV, repo pychef, workflow publish.yml, environment pypi).
   The workflow aborts if 0.2.0 already exists on PyPI.
2. Optional: run `test-publish.yml` manually first (TestPyPI has no 0.2.0).
3. **Read the Docs**: activate/build tag `v0.2.0`, make `stable` follow the newest tag, set the
   default version to `stable`, rebuild `latest`; check the three URLs
   (`/en/latest/`, `/en/stable/`, `/en/v0.2.0/`).
4. After PyPI shows 0.2.0: `pip install "cyberchef-py==0.2.0"` in a clean environment and run
   `tests/smoke_test.py`; then update this report.

No credentials were available in this environment (`gh` not authenticated; no token), so steps 1-4
could not be performed or verified here.
