---
name: ccloop-c7ee71c6-sess125-ROOTED-crash-consistency-354-empty-dir-recipe
description: sess125 ROOTED D-CRASH-CONSISTENCY-32-NOTERMINAL-354: trigger is an EMPTY shared dir, not board adjacency. Deterministic recipe. Same root as D-32NOD…
metadata:
  type: reference
tags: [defect, crash_consistency, rooted, dir-create-pace, rule4, yield-quantum]
---

# sess125 — D-CRASH-CONSISTENCY-32-NOTERMINAL-354 ROOTED

Open since 2026-08-02, three occurrences (sess43, sess45, sess90), all
framed as an unreproducible "in-board-only contention/starvation state"
with an "unidentified trigger". **The trigger is identified and the
defect now reproduces on demand.**

## THE RECIPE (deterministic, standalone, no board context)

    ./run.sh 32 caw prep_cluster      # fresh mkfs
    ./run.sh 32 caw crash_consistency # -> FAIL 90s/90s NO_TERMINAL_RECORD=32
    ./run.sh 32 caw crash_consistency # -> PASS 21s/90s 204/204

Measured on 0.11.452 / A1C4A05CB6356F02B8625F6, 2026-08-04:
- virgin fs: **FAIL 0/32 NO_TERMINAL_RECORD=32 [90s/90s]** hostload=16.35
  phases: datawrite min4/med32/max53, md5write min16/med28/max56
- re-run 2 min later: **PASS 32/32 [21s/90s]** hostload=**30.80**
  phases: datawrite ~1-2s, md5write ~1s

The PASSING run was at DOUBLE the host load of the failing one.

## WHY (mechanical, from tests/suite/crash_consistency.sh:20,38-45)

The test does `mkdir -p "$D"` and NEVER removes it. Filenames are
deterministic: `node${R}_f${i}` and `node${R}_f${i}.md5`.

- **First run after mkfs**: `.crash_consistency` is EMPTY. 32 nodes x 50
  files x 2 = **3200 NEW dirents** must be inserted. The dir grows
  sf -> block -> leaf -> node: block allocations, bestfree updates,
  btree splits — every one a cluster-coordinated mutation under 32-way
  concurrency.
- **Every re-run**: all 3200 names already exist. `dd ... of="$f"` is
  O_WRONLY|O_CREAT|O_TRUNC on an EXISTING inode — no dirent creation,
  **zero directory mutations**. `md5sum > "$f.md5"` likewise.

So the re-run is a COMPLETELY DIFFERENT WORKLOAD (3200 overwrites vs
3200 coordinated insertions).

## THE THREE HISTORICAL "CONTROLS" WERE WORTHLESS

sess43/45/90 each concluded "not reproduced — immediate re-run PASSED".
Those re-runs did not exercise the cause. The ledger's
"NOT reproduced in 3 immediate re-runs on the same build" evidence, and
sess90's "CONTROL ... STANDALONE = PASS 15s ... Inherent-pace hypothesis
refuted at this magnitude", are all invalid for the same reason.

## HYPOTHESES REFUTED THIS SESSION (each by direct measurement)

- **board/chunk adjacency** — chunk-2 prefix re-run: cc = 16s (had been
  83s). chunk-1 prefix + cc: cc = 15s. Neither reproduces.
- **mount-root dirent count** (ledger next_step item 2) — the standalone
  FAST run had MORE root entries than the slow one.
- **host writeback backlog from fio_perf** — SCST backstore
  `/home/steve/disk.img` via vdisk_fileio has **o_direct=1**; host
  Dirty was 3140 kB. No host page cache involved at all.
- **host load** — fast run at 30.80, slow at 16.35.
- **start skew** — 1s in BOTH the slow and the fast runs.

## THE PACE IS STRUCTURAL, NOT PATHOLOGICAL

3200 creates / ~70s = **22 ms per create**. The project's own measured
structural CAW publish is **19-21 ms/op** (TIMEOUT_BUDGETS, dlm_scaling
band). So the "slow" case is simply 3200 FULLY SERIALIZED publishes at
the known structural rate. There is no starvation state, and never was.
The ledger's `mechanism` field ("contention/starvation state, not a
fixed pace cost") is WRONG and must be corrected.

## STRUCTURAL ROOT: the yield quantum is AG-ONLY

`grep pag_dlm_yield_remaining` -> only `pag_*` (per-AG). The adaptive
yield quantum (xfs/xfs_mxfs_dlm.c:32622, 35265, 38285-38338) amortizes
the durable handoff across up to `ag_yield_quantum` (512) operations for
**AG** locks, halving on peer BAST and doubling when idle.

**The directory inode DLM lock has NO equivalent.** Every dirent
insertion therefore pays a full cluster-wide EX handoff + durable
publish. That is the structural root of the 22 ms/create pace.

## RE-ATTRIBUTION

D-CRASH-CONSISTENCY-32-NOTERMINAL-354 is a *manifestation* of
**D-32NODE-SHARED-DIR-CREATE-PACE** (major, "~42x more wall at 32
nodes") inside crash_consistency's 90s budget. Measured here: 35x
(70s vs 2s). Same root. Fix the dir-lock batching and both close;
they cannot be dispositioned independently.

## DISPOSITION STATUS
Still OPEN. Root is proven but there is no fix yet, so it is neither
DISPROVED (the slowness is real; RULE 0 says a timeout IS a failure)
nor FIXED AND VERIFIED. Next: design the directory-lock yield quantum.
