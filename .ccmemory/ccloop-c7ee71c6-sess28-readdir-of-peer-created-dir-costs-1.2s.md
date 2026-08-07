---
name: ccloop-c7ee71c6-sess28-readdir-of-peer-created-dir-costs-1.2s
description: NEW major defect: readdir of a peer-created dir = 1240ms/op while stat=4ms, open=45ms, rmdir=120ms. Plus the batch-attribution method trap.
metadata:
  type: project
tags: [mxfs, pace, readdir, rule0, D-READDIR-PEER-CACHED-DIR-PACE, sess28]
---

# sess28 — readdir of a peer-created directory costs ~1.2 s

Build 0.11.243 (`C3D864E1F8AB80753D23D6C`), 32/caw. Harness:
`tests/shared_unlink_pace.sh` (~60 s, **no aging needed**).

## The measurement

32 empty directories in one shared parent, each created by a different node
which still holds it cached. One pass from test1, **one syscall class per fresh
tree** so nothing is confounded:

| operation on a peer-created dir | total (32) | per op |
|---|---|---|
| `stat` | 133 ms | **4 ms** |
| `open(O_RDONLY\|O_DIRECTORY)` | 1463 ms | **45 ms** |
| `rmdir` | 3846 ms | **120 ms** |
| **`opendir`+`getdents`** | **39701 ms** | **1240 ms** |

Independently reproduced standalone: readdir-only pass over 32 dirs = 37495 ms
(1172 ms/op). **Control**: the identical 32 children created *locally* by the
same node = 152 ms total (4 ms/op) — so neither the shared parent nor the
removal is the bottleneck.

RULE 0: native XFS readdir of an empty dir is microseconds. ~10⁵× over.

## ⛔ THE METHOD TRAP — my first attribution was wrong

A batch `rm -rf` of those same 32 dirs measured **38344 ms**, and I recorded it
as *~1.2 s per removal*. Replacing the batch with an explicit per-op `rmdir`
loop over the identical shape gave **993–1052 ms total (31 ms/op)** — a 37×
difference for the same removals.

The 1.2 s belongs to the **readdir `rm -rf` performs on each child**, not to the
unlink. **Never attribute a batch wall to the operation the batch is named
after.** Split it per syscall, on fresh trees.

## What is already ruled out

- **Peer-side release latency** — REFUTED: `P51-REL drain_ms = 0,0,1` on the
  creators. Releasing is instantaneous.
- **Requester poll quantization** — REFUTED by construction:
  `MXFS_CAW_POLL_MAX_MS = 25`, inode fastpoll 2 ms for the first 64 ms.

## The narrowing that remains

Scoped probe census on the READER during a readdir-only pass over 32 dirs:

    P173-RELOAD-SELFREAD    110
    P-RELOAD-IDENTICAL       89
    P62-RELOAD-FORK-SHRINK   89
    P56-RELOAD-MERGE         88

≈ **three reload attempts per directory**. P173 is the sess14 bail: readdir
holds `ILOCK_SHARED` across iteration, so `mxfs_dlm_reload_inode` can never take
the write side and returns **without rebuilding**, leaving `i_dlm_stale` set so
the next access repeats it. The bail does not sleep — but it is reached only
*after* the reload has already read the inode cluster buffer
(`xfs_buf_relse(bp)` on the bail path), so each attempt pays a synchronous read
and achieves nothing.

**Next:** time the reload attempt (entry → P173 bail) and count attempts per
`getdents`. The 45 ms `open` vs 1240 ms `getdents` split says the cost is inside
`getdents`, not in acquiring the grant.

**Do NOT just widen the P173 spin** — sess14 measured that as a guaranteed
livelock for long readers and ~350 CPU-seconds per lap.

## Why this matters beyond its own cell

It is what makes `sustained_load` blow its 180 s budget at 32 nodes: rank 1's
`rm -rf $MNT/.sustained_load` was `rmrf=38379 ms` of a `38402 ms` setup phase —
and the criterion's own timer excluded that phase entirely, reporting
`per_op=198ms wall=3978ms` while timing out. `tests/suite/sustained_load.sh`
now has phase timers (`setup/rmrf/mkb/syn/bar1/mkd/bar2/twall`).
