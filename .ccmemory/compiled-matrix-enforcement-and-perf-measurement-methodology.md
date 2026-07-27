---
name: compiled-matrix-enforcement-and-perf-measurement-methodology
description: Compiled: how the 4-condition/32-node matrix was made REAL-enforced (RULE0_CALIBRATE=0) + the perf-measurement methodology — baseline pairing, host h…
metadata:
  type: project
tags: [compiled, ccloop-0220f43f, matrix, fio, rule0, rule4, methodology, host-noise]
---

# Matrix enforcement + perf-measurement methodology (ccloop 0220f43f sess2)

Compiled from [[ladder-rung-health-gate-and-baseline-pairing-fix]],
[[fio-noise-pattern-and-raw-ceiling-refresh]],
[[cawd-single-node-paired-boundary-hugging-not-regression]],
[[ccloop-0220f43f-CRITERIA-MET-4conditions-32nodes]].

Outcome: all 4 conditions (tcp/cawp/cawd/caw) × N=1,2,4,8,16,32 at 100% PASS,
**real-enforced**, on one build (0.11.39 / `420FBA2893A16457AEFA58C`, zero kernel
source changes this session — only `run.sh` and `scripts/ladder_rung.sh` moved).
Marker: `.ccloop/runs/0220f43f-252a-41ff-9c28-6377ebfe0d3b/criteria-met`.

## The central finding: a green board was not a real board

`matrix_check.py` only checks `cell["status"] != "PASS"`. It does **not** inspect
the `[CALIBRATION: budget not enforced]` tag, nor compare `elapsed_s` vs
`budget_s`. Meanwhile `scripts/ladder_rung.sh` — the harness that produced
essentially the entire historical board, across ccloop runs 72513a13, 5d123e7b
and 0220f43f — **hardcoded `RULE0_CALIBRATE=1` on every `run.sh` call**. Under
calibrate mode `run.sh::record()` skips the RULE-0 elapsed>budget→FAIL override
and inflates kill_budget/tt 20×.

So every cell ever produced by `ladder_rung.sh` was calibration-tagged and had
never been budget-gated. At sess2 start: **426/548 non-xfs cells flagged**. Prior
sessions had reported `matrix_check.py --cond all` = 100% PASS more than once;
none of those were enforced runs.

Of the 16 cells where elapsed actually exceeded budget, 15 were stale pre-fix
data (the drc / posix_multi / cache_coherency O(T²) reshapes landed after those
records) and 1 was 1s of ssh noise (2/tcp precond_readiness, 11s vs 10s) — no
real bug hid in there, but that was only knowable after auditing.

**Fix**: `scripts/ladder_rung.sh` ~31-41, both the `run()` helper and the initial
`prep_cluster` call, changed to `RULE0_CALIBRATE="${RULE0_CALIBRATE:-1}"`.
Default behavior for other callers is unchanged; `RULE0_CALIBRATE=0
scripts/ladder_rung.sh <N> <cond>` now does a real run — exact manifest budget as
kill_budget, RULE-0 override live.

Then every cell was re-run for real: 24 rungs (4 cond × 6 N), condition by
condition, N ascending. Post-sweep audit: 0 calibration-tagged, 0 elapsed>budget,
all 519 non-xfs cells timestamped inside the session window (03:14-07:14Z).

**Standing rule: a `matrix_check.py` PASS is not evidence of criteria met until
every cell was produced under `RULE0_CALIBRATE=0`.** Audit by scanning
criteria.json for `CALIBRATION` in `reason`, `elapsed>budget`, and
`elapsed==0-but-not-flagged`.

## Two stale-baseline risks in the fio comparison chain

`tests/suite/fio_perf_vs_xfs.sh` picks its yardstick by N:

- **N=1** → `.xfs_fio_baseline.<cond>.json`, a 1-stream native-XFS baseline.
- **N>1** → `.raw_fio_ceiling.<cond>.json`, the RAW N-sharer concurrent-write
  ceiling, filesystem bypassed. This is deliberate: a shared device physically
  cannot deliver its 1-stream bandwidth to N concurrent sharers, so comparing
  N>1 mxfs against the 1-stream baseline is the wrong yardstick **by physics**,
  not by bug.

Both files go stale, and each has a different refresh economics:

`.xfs_fio_baseline` is now refreshed **automatically every rung** by
`ladder_rung.sh`'s health gate. Critically, it must use the **same device the
real condition uses** — xfs mode's own `DEV_DEFAULT` only covers cawp/tcp's
`/dev/sda`; cawd and caw need an explicit `MXFS_DEV` override
(`/dev/disk/by-path/...shared-lun-0`, `/dev/mapper/mpatha`) or the "baseline"
measures the wrong device entirely.

`.raw_fio_ceiling` is **not** covered by the health gate — `raw_fio_ceiling.sh`
takes ~5 min and requires the entire cluster unmounted on all 32 nodes (it writes
raw block I/O to the shared LUN and its own safety check scans all 32 nodes and
refuses if anything is mounted; `RAWCEIL_FORCE=1` overrides it — don't, the check
is real). Procedure: run it **once per condition**, right after the rig switch, or
right after a suspicious N>1 `fio_perf_vs_xfs` FAIL. One invocation captures all
of 2/4/8/16/32.

## The per-rung health gate

Every `ladder_rung.sh` invocation now, **before** the real N/COND prep:

1. `health_gate` — best-effort `sudo -n swapoff -a` / `sync` / drop_caches /
   `sudo -n swapon -a`. Failures logged, non-fatal (perf hygiene, not
   correctness-load-bearing).
2. Refresh `.xfs_fio_baseline.${COND}.json` via a throwaway N=1 native-XFS
   prep+fio_perf on the correct device.
3. Then `MXFS_FORCE_PREP=1 ./run.sh $N $COND prep_cluster` — no wasted double
   prep, since the LUN was getting reformatted back to mxfs anyway.

## Host noise is the dominant false-FAIL source — and clyde is a shared host

clyde runs a vLLM inference server (~10GB RSS), a game worldserver, and a trading
engine alongside 32 test VMs (~38.6GB RSS) on 94GB RAM, 70GB+ routinely used.

The 1/tcp case, root-caused end to end: `free -h` showed swap **8.0Gi/8.0Gi
FULL** (108Ki free), loadavg-15 = 15.88. bench.json history for the same test,
same code: 2026-07-05 ~1560-1600 MiB/s → 07-19T10:59 978 → 07-19T22:03 382 →
07-19T22:38 312 (the recorded FAIL). **A 3-5× swing with zero code changes.** The
`.xfs_fio_baseline.tcp.json` it was compared against had been captured at 17:25Z
— 5+ hours earlier, demonstrably different host state.

`tests/tooling/fio_vs_xfs_baseline.sh` already runs 4 position-balanced
interleaved xfs/mxfs rounds + trimmed mean specifically to fight noise, but a
swap-thrashing host still pushed 3 of 4 rounds under threshold (round ratios
37, 29, 66, 186 — only the lucky 186 would have passed alone).

After `swapoff -a && swapon -a` (58s to page 8GB back; `free -h` showed 24Gi
available first, so no OOM risk) and a fresh pairing: `fio_vs_xfs_baseline`
worst_write 93% (from 51%), and mxfs seqW 697 MiB/s vs freshly captured native
XFS 679 MiB/s — **mxfs faster than native XFS**. No code change was needed or
made.

## Distinguishing noise from regression

Confirmed 3× during the sweep that a perf-comparison FAIL can clear on an
immediate retry at identical cluster state: 1/tcp `fio_perf_vs_xfs` +
`fio_vs_xfs_baseline`, 1/cawp `single_node_paired` (107% > 105%, round_ratios
81/90/124/134, instant PASS 33s/90s right after a rig switch's 32-VM power-cycle
storm), 2/cawp `fio_perf_vs_xfs` (randW 31% against `wsrc=raw-ceiling`, PASS at
92%+ after refreshing the ceiling).

**Every retry-confirmed PASS landed comfortably (92-158%+), never a marginal
squeak.** That is the discriminator: this is "the first sample was unlucky," not
"lowering the bar."

Even medians are noisy at the source — one cawp N=32 seqW ranged **224-2580
MiB/s across 3 back-to-back samples** of the same condition and N. Hence
median-of-3 (`RAWCEIL_SAMPLES`) and never single samples.

### The boundary-hugging case is its own category

1/cawd `single_node_paired` (rsync of an 8714-file tree, 4 position-balanced
rounds, trimmed-mean ratio, threshold ≤105%) did **not** clear on one retry.
RULE 4: six independent real trials were gathered rather than accepting the first
lucky PASS.

| # | ratio | round_ratios | verdict |
|---|---|---|---|
| 2 | 161% | 112,119,204,597 | FAIL (one wild outlier) |
| 3 | 107% | 103,106,109,119 | FAIL (tight, no outlier) |
| 4 | 105% | 99,103,107,127 | PASS (exactly at threshold) |
| 5 | 99%  | 96,98,100,103 | PASS |
| 6 | 94%  | 72,87,102,113 | PASS |
| 7 | 105% | 96,104,106,115 | PASS |

Median = 105%, exactly the threshold. Distribution roughly **symmetric** around
100-105% — several samples beat native XFS; no consistent directional slowdown.
Loadavg was elevated (21-23 vs the usual 13-16) from the cumulative multi-hour
sweep plus a `raw_fio_ceiling.sh` capture immediately prior. Diagnosis:
measurement noise on an inherently short (~2.7-3.9s per leg) workload sitting at
the boundary, not a regression.

**The shape test**: a real regression is consistently >>105% in the same
direction every time. Boundary-hugging is a small symmetric spread around the
threshold. Do not conclude "cawd is broken" from one FAIL without checking which
shape it is. Untested candidate hypothesis if it ever hardens on a fresh host at
>110-120% across trials: direct-iSCSI's guest-initiated session may have
different per-op latency than SCST passthrough, interacting differently with
mxfs's per-op CAW/journal overhead. No evidence either direction yet.

## Do NOT

- Do not widen `FIO_MIN_PCT` / `RATIO_THRESHOLD` to make these pass.
- Do not skip re-verification after a retry — confirm via
  `python3 scripts/matrix_check.py --cond <cond> --nodes <N>` that the cell is a
  real (non-CALIBRATION) PASS before moving on.
- Do not treat a fresh-and-paired sub-70% result as noise **twice**. If a fresh
  ceiling + fresh mxfs measurement, paired in time, land under 70% more than
  once, that graduates to a real kernel write-path investigation.
- If host-noise retries start recurring more than ~1-in-4 rungs, that crosses
  from noise into a real investigation.

## Shell exit-status handling in run.sh is a recurring defect class

This session also fixed `run.sh::run_none()`: `out=$(cmd | grep ...); rc=$?`
captured **grep's** exit status rather than `timeout`'s, so a killed test could
be mislabeled "no-result" instead of "timeout." Fixed by capturing `rc` directly
off `timeout` with no pipe between, plus a bounded 3-attempt retry for the
empty-output/non-124 case (an ssh/connection-layer hiccup — `lib.sh::finish()`
always emits a RESULT: line for any test that actually ran, so empty output is
never a real functional failure).

**This is a class, not a one-off.** The same "pipeline swallows the exit status
you actually wanted" defect exists elsewhere in run.sh — see
[[runsh-ssh-node-pipeline-swallows-remote-exit-status]] for the `ssh_node()`
instances, where the consequence was worse (the check's verdict was decided
entirely by whether the target host had an SSH login banner). When auditing
run.sh, grep for `$?` after a pipeline and for any function whose body ends in a
pipe but whose exit status is consumed by a caller.

## Scope notes

- The NET2 redesign (ccloop 5d123e7b, "success.md", DLM epoch rearchitecture)
  reached its own DONE state earlier and is a **different** task — do not conflate.
- `soak` ran at its default 30s smoke length throughout, as it always has in the
  ladder. `TIMEOUT_BUDGETS.md`'s "1h+5m" note refers to a separate deliberate
  long exercise, not part of this matrix.
- state.md / criteria.json / bench.json / VERSION are the durable cross-run
  ground truth — **not** any single ccloop run's memory notes. Multiple ccloop
  run IDs (72513a13, 5d123e7b, 0220f43f) have chased identical/overlapping
  criteria.
