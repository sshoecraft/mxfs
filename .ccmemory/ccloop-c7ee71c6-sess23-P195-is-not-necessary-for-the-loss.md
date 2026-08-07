---
name: ccloop-c7ee71c6-sess23-P195-is-not-necessary-for-the-loss
description: sess23 MEASURED: dirent_durability durable_loss=3 mkdir_err=0 in a window where dirent_publish_integrity read stale_base_mutations=0 — P195 is NOT ne…
metadata:
  type: project
tags: [ccloop-c7ee71c6, sess23, D-SILENT-MKDIR-LOSS, P195, measurement]
---

# sess23 — P195 is NOT a necessary precondition for the silent mkdir loss

## The measurement

16/caw, build 0.11.193 (`1E80BA2BA779A20CE5ACE17`), one `run.sh` invocation,
`dirent_durability` immediately followed by `dirent_publish_integrity` (which
scans the window `dirent_durability` stamps):

    dirent_durability         FAIL  nodes_pass=4/16 states:FAIL=12
                                    rounds=30 durable_loss=3 late_ok=17 mkdir_err=0
    dirent_publish_integrity  PASS  nodes_pass=16/16
                                    stale_base_mutations=0 unlanded_at_unlock=0
                                    probe=1 window=1

**Three directory entries durably lost, `mkdir(2)` returned success on all of
them (`mkdir_err=0`), and the P195 precursor fired ZERO times in that window.**

## Why this matters

state.md (sess21/sess22) describes `P195-STALE-BASE-ALREADY-DIRTY` as "the
DETERMINISTIC predicate" for D-SILENT-MKDIR-LOSS, and
`dirent_publish_integrity` exists specifically because the symptom is
intermittent while the precursor was believed to fire reliably. This run shows
the symptom WITHOUT the precursor.

Therefore at least one of these is true, and the next session must determine
which:
1. there is a **second producer** of the loss that does not go through an
   epoch-stale-base mutation; or
2. P195's predicate does not actually capture the mechanism it is credited with;
   or
3. the window scoping in `dirent_publish_integrity` mis-scanned this particular
   run (it reads a `MXFS_DIRENT_WINDOW` marker stamped by `dirent_durability`).

**(3) IS RULED OUT (verified).** `dirent_durability` stamps
`MXFS_DIRENT_WINDOW` to /dev/kmsg at the START of its run, before the workload
(tests/suite/dirent_durability.sh:65), and `dirent_publish_integrity` scans
everything after the LAST such marker. When it ran, the last marker was that
failing run's own start, so the scanned interval provably covered every losing
round. The loss occurred with P195=0 in a correctly scoped window.

That leaves (1) a second producer, or (2) P195 mis-models the mechanism.

## Do not conclude from this that the board is wrong

Both criteria are behaving as designed; they simply disagree about this run,
which is exactly the kind of disagreement a two-criteria design exists to
surface. `dirent_publish_integrity` was red 12/16 earlier in the SAME session
(`stale_base_mutations=1..4`, `unlanded_at_unlock=1` on test4/12/14/15), so the
probe does fire — just not in the window where the loss happened.

## Reproduction rate observed this session

`dirent_durability` @16/caw on 0.11.193: 1 FAIL (durable_loss=3) in 3 runs;
the other two PASSed with `durable_loss=0 late_ok=20/22 mkdir_err=0`. Consistent
with the documented "~1 run in 10" but at 16 nodes it appears more often.
Single-run deltas remain worthless for A/B on this defect.
