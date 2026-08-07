---
name: ccloop-c7ee71c6-sess20-atomic-bug-harness-truth-and-tcp-wedge
description: sess20b: sleeping SCSI read under spinlock FIXED; sf_mkdir_storm was over-reporting (lag != loss); whole CAW column green; new 32/tcp rsync wedge.
metadata:
  type: project
tags: [ccloop, c7ee71c6, sess20, atomic-context, sfstorm-harness, 32tcp, ag-starvation]
---

# sess20 part B — the harness was lying, and a kernel-atomic bug

## 1. "BUG: scheduling while atomic" — blocking SCSI read under a spinlock

Found by re-running a STALE board cell (16/caw `soak`). 112-126 hits PER NODE
on all 16 nodes, from xfsaild and the mxfs kworkers:

    mxfs_submit_partial_inode_write      <- holds spin_lock(pag_ici_lock)
      -> mxfs_v5_dlm_inode_held -> mxfs_dlm_caw_held -> find_slot -> read_slot
         -> mxfs_pal_scsi_read_fua_bdev -> blk_execute_rq
            -> wait_for_completion_io_timeout -> schedule()

sess19's `dir_nl_require_grant` consults the DLM inside the partial-write slot
loop; on CAW the only authority is the on-disk slot table, so that is a
BLOCKING SCSI READ under a spinlock.

FIX v0.11.162: `mxfs_v5_dlm_inode_held_nb()` — in-memory mirror on TCP,
-EWOULDBLOCK on CAW. Atomic caller treats unknown as AUTHORIZED (treating it as
"not held" strands a fresh dir cluster-wide, proven sess14). Also gated the
P185 conversion audit behind `mxfs.sfconv_audit=0` (blocking read inside a live
transaction). VALIDATED: cleared rings, re-ran soak, 0 hits on every node.

**LESSON: `./showstat.sh` REPLAYS criteria.json. A green cell is a CACHE.**
This defect sat undetected because the cell had been green since 2026-07-25.

## 2. tests/sf_mkdir_storm.sh WAS OVER-REPORTING — the big correction

It verified round K-2 at the top of round K and called any inconsistency loss.
It is not: a name that has not propagated YET is indistinguishable from one
that is gone. Decisive: a `MXFS_STORM_NOTEARDOWN=1` run flagged 70 round-checks
in-run; the post-settle census across all 32 nodes found **0 still wrong**.

Harness now: first FAIL only marks PENDING → `recheck_pending` retires it as
**LATE-OK** or convicts it as **DURABLE-FAIL**; a round the teardown was asked
to remove is **UNRESOLVED**, never a verdict (a concurrent `rm -rf` walks nlink
down and was fabricating "nlink=4 visible=2 expected=32" on 24 nodes); teardown
lag 4 → 10 rounds; host-side settled census; only DURABLE-FAIL fails the run.

Why the lag: **32 concurrent mkdirs into ONE dir = min 24 ms, p50 810 ms,
p90 1382 ms, max 1573 ms, 0 failures** (~49 ms per serialized DLM tenure × 32).
A round barely fits the 2 s slot. Harness calibration, not a coherency defect.

**Result: `tests/sf_mkdir_storm.sh 30 32 2 1` now PASSES.**

Every prior session's storm numbers (21/28 "failing rounds", 400-700 "losses")
were dominated by this artifact. Do NOT compare against them.

## 3. Whole CAW column re-measured on E306171F1E7A2C6B0804CA5

1/caw 30/30, 2/caw 20/20, 4/caw 20/20, 8/caw 20/20, 16/caw 20/20, 32/caw 20/20
— all PASS, all fresh. sess19's two red cells (`fence_during_write`,
`dir_reuse_coherency`) are green on a real measurement.

Use a BARE `./run.sh <N> <dlm>` — it covers every applicable cell. Give it the
full wall: killing it mid-sweep records unrun tests as FAIL "aborted" (1/caw
needs >10 min; dkms_install alone is 209 s).

## 4. NEW OPEN: 32/tcp rsync_paired wedge (AG-DLM starvation)

`nodes_pass=0/32 NO_TERMINAL_RECORD=32` at its 60 s budget; solo re-run still
wedged at 6m40s. Passes at 32/caw in 14 s.

    P12-AGBAST-RX ag=1  holders=2 cached=0 readopt=7  page_ms=448512 holder=rsync
    P12-AGBAST-RX ag=18 holders=2 cached=0 readopt=49 page_ms=781308 holder=rsync
    P36-RETRY ino=0 type=3 ag=24 mode=EX retries_left=22 comm=rsync

A peer's AG BAST pending **448-781 s** while local holders never reach 0 and
`readopt` climbs to 49 — the local fast path keeps re-adopting the cached AG
ahead of the waiting peer. AG-level ping-pong starvation, TCP-only so far.
`mxfs_ag_yield_adaptive` exists to bound this and is not bounding it at 32.

**Rig note:** tcp prep needs `MXFS_DEV=/dev/mapper/mpatha` — `/dev/sda` is
claimed by multipath on this rig, so the default tcp device fails mkfs.
