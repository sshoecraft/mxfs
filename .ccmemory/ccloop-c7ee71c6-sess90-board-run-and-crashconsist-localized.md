---
name: ccloop-c7ee71c6-sess90-board-run-and-crashconsist-localized
description: sess90: owed 32/caw board RUN on 0.11.420 (no proto_gen-3 regression) + crash_consistency FAIL localized to the O_SYNC write phases; 2 hypotheses ref…
metadata:
  type: reference
tags: [crash_consistency, board, proto_gen, rule0, pace, ccloop]
---

## The 3-session-owed regression board is RUN

Fleet + tree both `33018595D555FBE463F017B` (0.11.420, proto_gen 3), verified
before measuring. Fresh prep 53s, 32/32 mounted and converged.

**Result at 32/caw: 23 PASS, 3 FLAKY, 1 POLICY, 1 FAIL.**
The proto_gen 3 bump did NOT regress the board. The 3 FLAKY cells
(cache_coherency, scaling_curve, dir_reuse_coherency) all passed this run and
are pre-existing ledger entries. `open_defects` is red by design (RULE 6).

Ran it in 6 chunks under the 10-min foreground cap, each timeout = sum of that
chunk's per-test budgets + harness overhead (RULE 0 honest, no widening).

## crash_consistency: FAILED, and localized for the first time

`FAIL nodes_pass=0/32 NO_TERMINAL_RECORD=32 hostload=24.00 [90s/90s]` — the
third occurrence (sess43 opener, sess45, now sess90).

New persistent tool: **`tests/cc_phase_attrib.sh`** — harvests the `mxfs-CCph
rank=N PHASE=x` markers cluster-wide, prints per-node phase walls, per-phase
min/med/max, and a terminal-phase census. This is the instrument the opener's
next_step asked for, and it answered.

### Where the time goes (failing run)
| phase | min | med | max |
|---|---|---|---|
| datawrite | 5 | 32 | **56** |
| md5write | 14 | 31 | **48** |
| dropcaches | 4 | 4 | 5 |
| verify | 8 | 8 | 9 |

Critical path = slowest node's datawrite+md5write = **80s**, +4 +8/9 = **~92s
vs a 90s budget**. ALL excess is in the two O_SYNC write phases.

### NO_TERMINAL_RECORD is NOT a capture bug
`crash_consistency.sh:143` blocks in `coord_barrier cc_done` AFTER
`PHASE=count-done`. 15 nodes (2,3,4,17-28) reached count-done; 17
(1,5-16,29-32) never left dropcaches-done. One straggler stops every node from
reaching `coord_done`, so all 32 report no verdict even though 15 finished.
The terminal-phase census is the discriminator. Do not diagnose the FS from
the bare NO_TERMINAL_RECORD count.

## Two hypotheses REFUTED by measurement

1. **Inherent shared-dir create pace.** Standalone re-run on the SAME build and
   SAME aged mount 17 min later: PASS 15s/90s, 204/204, hostload 17.37.
   datawrite max **2s** (was 56 = 28x), md5write max **1s** (was 48 = 48x),
   all 32 reached barrier-done-done. 3200 O_SYNC creates cost ~2s when the
   cluster is quiescent. The pace is fine; this is a contention STATE.
2. **rsync_paired adjacency** (the opener's leading hypothesis, correlated 3/3
   because it precedes crash_consistency in board order). Ran
   `rsync_paired -> crash_consistency` back-to-back: rsync_paired PASS 22s/60s
   hostload 29.49, crash_consistency PASS 18s/90s hostload **33.96** — higher
   load than the failure. Adjacency alone does not reproduce.

Combined with the opener's 3 re-runs passing at hostload 23.6/43.1/44.3, both
simple host-load correlation AND preceding-test adjacency are excluded as
sufficient causes.

## Kernel-side evidence (unrooted trigger)

Window 04:40:29-04:41:48, slowest node (test7, datawrite 56s) vs fastest
(test10, 5s): total mxfs kmsg 14750 vs 8280. `P50-RD` 6322 vs 2115;
`P34-LEAF-DRAIN` 813 vs 374. Dominant inode on both is `ino=46671555` = the
shared `.crash_consistency` dir (6019 vs 4262). Simultaneously the mount ROOT
`ino=128` is in a suppressed-BAST storm (`mxfs_dlm_bast_notify: 150 callbacks
suppressed`, repeated P-DIRBAST/P7B-BASTNOTIFY) with `P70-BP ENTRY
held_ms=301785` on test7 vs `99004` on test10.

Within one failing run the per-node spread is 5s..56s for IDENTICAL work — a
starvation signature, not uniform slowness.

## Next session

Ledger `next_step` is updated with the full plan. The sharp one: **bisect the
in-board prefix**. The FAIL needs board context, not any single predecessor —
run crash_consistency after progressively longer prefixes (chunk1; chunk1+2;
...) with `cc_phase_attrib.sh` after each, and find the shortest prefix that
pushes datawrite past ~10s. That converts an intermittent into a recipe.
Strong suspect: every criterion creates its own `.<test>` dir in the mount
root, so root dirent count grows monotonically across the board — test by
pre-populating the root to the same entry count.

Do NOT close on a clean run: this has now passed immediately after failing on
three separate occasions.
