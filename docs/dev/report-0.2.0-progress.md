# PyChef 0.2.0 development report (in progress)

## Baseline (commit fc11d4e, branch main, version 0.1.1, Python 3.13.5 in uv env)
- 502 registered operations, 904 tests passed, 0 failed, 29.6 s
- Coverage 85.01 % (statement + branch, total)
- ruff check / format / ty: clean
- `import pychef`: ~55 ms in `pychef.operations.by_operation` (eager import of all
  modules), ~70 ms total; ~15 MiB traced allocation after import
- Throughput: see `baseline-benchmark-0.1.1.txt` (`scripts/benchmark.py`).
  Notable slow spots: SHA2 ~0.6 MiB/s (pure Python), To/From Hex ~6.5 MiB/s,
  XOR ~14 MiB/s.  `uv build` / wheel size not yet measured.

## Done so far
- Phase 1: `ExecutionPolicy`, per-execution `ExecutionContext` (shared by nested
  Fork/Subsection, step/branch/depth/input/output/trace budgets, cooperative
  deadline and cancellation), structured error hierarchy, absolute step indices.
- Phase 2: network operations gated by policy; connection pinned to validated
  addresses (no second DNS lookup), proxies ignored, port/userinfo validation,
  IPv4-mapped/6to4/NAT64/Teredo unwrapping, default port bug (443 for http) fixed.
- Phase 3.1: delimiter escapes follow CyberChef `parseEscapedChars`; empty Fork
  delimiter no longer crashes.
- Tests: 1036 passed (132 new).

## Not done yet (open)
P1: lazy loading + manifest, OperationSpec metadata API, `Pipeline.iter_transform`
and Pipeline policy/trace integration, CyberChef version diff, compatibility status
classes, differential tests, property/fuzz tests, performance optimisation.
P2: CI matrix additions, docs (`docs/security.md`), changelog, release checks.
