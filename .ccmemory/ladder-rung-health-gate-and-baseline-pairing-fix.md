---
name: ladder-rung-health-gate-and-baseline-pairing-fix
description: RULE 4: 1/tcp fio_perf_vs_xfs+fio_vs_xfs_baseline FAILs (51-59%) were host swap-exhaustion + stale baseline, not mxfs bug. Fixed in ladder_rung.sh: h…
metadata:
  type: project
tags: [ccloop-0220f43f, fio_perf, rule4, host-hygiene, ladder_rung, matrix]
---

## Context: ccloop 0220f43f session 2, continuing the "4 conditions in conditions.md to 32 nodes" task

Same overall task as ccloop runs 72513a13 and 5d123e7b before it (multiple ccloop
run IDs on this repo have chased identical/overlapping criteria — see
`.ccloop/runs/*/criteria.md`, all say "get all 4 conditions in ./conditions.md
working 100% up to 32 nodes"). state.md / criteria.json / bench.json / VERSION
are the durable cross-run ground truth, NOT any one ccloop run's memory notes.

## Finding 1: matrix_check.py only checks `status`, not budget enforcement

`scripts/ladder_rung.sh` (the harness used for essentially the entire historical
board) hardcodes `RULE0_CALIBRATE=1` on every `run.sh` call. Under calibrate mode,
`run.sh`'s `record()` SKIPS the RULE-0 elapsed>budget override, and kill_budget/tt
are inflated 20x — so literally every cell ever produced by ladder_rung.sh is
tagged `[CALIBRATION: budget not enforced]` in its `reason` field and was NEVER
really budget-gated. `matrix_check.py` (scripts/matrix_check.py) only checks
`cell["status"] != "PASS"` — it does NOT look at the CALIBRATION tag or compare
elapsed_s vs budget_s. So a 100% PASS from `matrix_check.py --cond all` does NOT
by itself mean the matrix is real-enforced. As of ccloop 0220f43f sess2 start:
426/548 non-xfs cells were CALIBRATION-flagged; of the 16 cells where elapsed
actually exceeded budget, 15 were stale pre-fix data (dir_reuse_coherency /
posix_multi / cache_coherency O(T²) fixes landed after they were recorded) and
1 was 1s of ssh noise (2/tcp precond_readiness, 11s vs 10s budget) — not a real
bug. Audit script: see scratchpad or rerun the pattern (scan criteria.json for
`CALIBRATION` in reason / elapsed>budget / elapsed==0-but-not-flagged).

**Fix applied**: `scripts/ladder_rung.sh` lines ~31-41 changed
`RULE0_CALIBRATE=1 ./run.sh ...` to `RULE0_CALIBRATE="${RULE0_CALIBRATE:-1}" ./run.sh
...` in both the `run()` helper and the initial `prep_cluster` call — default
behavior unchanged (still calibrate=1 if caller doesn't set it), but now
`RULE0_CALIBRATE=0 scripts/ladder_rung.sh <N> <cond>` does a REAL run: exact
kill_budget = manifest budget (no 20x), and `record()` applies the RULE-0
elapsed>budget→FAIL override for real. This is now how the whole matrix must be
re-verified — a plain `matrix_check.py --cond all` PASS is not sufficient
evidence of "criteria met" until every cell was produced under `RULE0_CALIBRATE=0`.

## Finding 2 (RULE 4 loop, root-caused): 1/tcp fio_perf_vs_xfs (59%) + fio_vs_xfs_baseline (51%) FAILs

Hypothesis: host resource pressure (not an mxfs code regression) was suppressing
measured write throughput, AND the `.xfs_fio_baseline.tcp.json` file being
compared against was stale (captured hours earlier under different host load).

Instrumentation/measurement:
- `free -h` at investigation start: swap 8.0Gi/8.0Gi used (FULL), only 108Ki
  free swap, host loadavg 15-min=15.88. clyde runs unrelated heavy neighbor
  workloads (vLLM inference server ~10GB RSS, a game "worldserver" process, a
  trading engine) alongside the 32 test VMs (~38.6GB RSS) — 94GB total RAM,
  70GB+ used routinely.
- bench.json history for 1n/tcp fio_perf seqW: 2026-07-05 ~1560-1600 MiB/s;
  2026-07-19T10:59 978 MiB/s; 2026-07-19T22:03 382 MiB/s; 2026-07-19T22:38 312
  MiB/s (the recorded FAIL, vs baseline's 525 = 59%). 3-5x swing with zero code
  changes = host noise, not product regression. `.xfs_fio_baseline.tcp.json`
  was captured at 17:25Z; the failing mxfs measurement was at 22:38Z — 5+ hours
  apart, and the host was demonstrably NOT in the same state (see swing above).
- `tests/tooling/fio_vs_xfs_baseline.sh` already does 4 position-balanced
  interleaved xfs/mxfs rounds + trimmed mean specifically to fight host noise,
  but a truly overloaded host (swap thrashing) can still push 3-of-4 rounds
  below threshold (round ratios seen: 37%,29%,66%,186% — only the lucky 186%
  round would have passed alone).

Fix (proven, not guessed): `sudo swapoff -a && sync && drop_caches && sudo
swapon -a` (58s to page 8GB back from swap.img; safe, `free -h` showed 24Gi
"available" before doing it so no OOM risk) then re-ran BOTH tests fresh:
- `fio_vs_xfs_baseline`: worst_write 93% (was 51%) — PASS, real (non-calibrate),
  132s/180s.
- Fresh-paired xfs baseline (`MXFS_TEST_ENV="XFS_BASELINE=.xfs_fio_baseline.tcp.json"
  ./run.sh 1 xfs fio_perf` immediately followed by `./run.sh 1 tcp fio_perf`):
  mxfs seqW=697 MiB/s vs freshly-captured xfs seqW=679 MiB/s (mxfs FASTER than
  native XFS in this pairing) → `fio_perf_vs_xfs` PASS.

**No mxfs code change was needed or made** — this was a measurement-methodology
bug (stale/unpaired baseline + didn't control for host memory pressure), not a
functional defect. Confirmed via matrix_check.py --cond tcp --nodes 1: 29/29 PASS.

**Permanent fix landed in `scripts/ladder_rung.sh`** (not a one-off manual fix):
every rung invocation now, before the real N/COND prep:
1. `health_gate`: best-effort `sudo -n swapoff -a` / drop_caches / `sudo -n
   swapon -a` (failures logged, non-fatal — perf hygiene, not correctness-load-
   bearing).
2. Refreshes `.xfs_fio_baseline.${COND}.json` via a throwaway N=1 native-XFS
   prep+fio_perf run, using the SAME device the real condition uses (xfs mode's
   own DEV_DEFAULT only covers cawp/tcp's /dev/sda — cawd/caw need explicit
   `MXFS_DEV` override to `/dev/disk/by-path/...shared-lun-0` / `/dev/mapper/
   mpatha` respectively, or the "baseline" would measure the wrong device).
3. THEN the real `MXFS_FORCE_PREP=1 ./run.sh $N $COND prep_cluster` (was going
   to reformat the LUN back to mxfs anyway after the xfs detour — no wasted
   double-prep).

Net effect: every future rung run via `RULE0_CALIBRATE=0 scripts/ladder_rung.sh
<N> <cond>` self-heals host pressure and self-pairs its baseline — the
fio_perf_vs_xfs / fio_vs_xfs_baseline FAIL class should not recur structurally
(though a genuinely saturated host during the ~90s window between baseline
capture and mxfs measurement could still in principle cause noise — watch for
recurrence and escalate to a real code investigation only if it survives a
clean host + fresh pairing, per RULE 4).

## Verified end-to-end

Full `RULE0_CALIBRATE=0 scripts/ladder_rung.sh 1 tcp` run (through the patched
script, all 8 chunks) went PASS on every test observed including fio_perf_vs_xfs,
dir_reuse_coherency (52s/120s), soak, dkms_install, single_node_paired — see
`tests/logs/ladder_rung_1tcp.log`. This is the template for the remaining
real-enforcement sweep across tcp/cawp/cawd/caw x 1/2/4/8/16/32.
