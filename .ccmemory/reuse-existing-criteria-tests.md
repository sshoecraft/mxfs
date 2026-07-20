---
name: reuse-existing-criteria-tests
description: Before writing ANY test/bench, check tests/criteria/ AND bench/ AND tools/ for an existing implementation and adapt its logic (incl. bench.json recor…
metadata:
  type: feedback
---

**Before writing any MXFS test OR benchmark, check for an existing
implementation and reuse its logic — do NOT reinvent.** Look in ALL of:
- `tests/criteria/` — ship-gate verifiers (correctness, timing, thresholds).
- `bench/` — `phase0_fio_multinode.sh` (4 canonical fio workloads),
  `rsync_bench.sh`; `bench/README.md` = methodology + bench.json schema.
- `tools/` — `mxfs_multinode_bench.sh` (rsync, APPENDS to bench.json),
  `mxfs_bench.sh`/`mxfs_bench.c` (single-node dd bench).
- `SUCCESS_CRITERIA.md.old` maps criteria → scripts.

**Two reinvention failures this session (2026-06-14):**
1. Rewrote ~7 tooling tests that existed in tests/criteria/ (online_resize etc).
2. Wrote fio_perf / fio_vs_xfs_baseline fresh, taking only the workload PARAMS
   from bench/phase0_fio_multinode.sh and DROPPING the bench.json recording the
   existing bench scripts had. Perf numbers must land in bench.json (the perf
   history store), not only criteria.json.

**How to apply:** for any perf/bench test, the existing bench scripts already
have (a) the proven workloads, (b) bench.json append in the README schema, and
(c) cache methodology (drop host+guest caches; O_DIRECT). Adapt that. Perf tests
(fio_perf, fio_vs_xfs_baseline, single_node_paired, rsync_paired, scaling_curve)
ALL should append to bench.json. The new HARNESS (criteria.json status, category
model, showstat) is the new value — test/bench BODIES should be lifted from the
existing scripts, not rewritten.
