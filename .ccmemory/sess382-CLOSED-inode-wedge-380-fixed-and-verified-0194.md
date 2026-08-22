---
name: sess382-CLOSED-inode-wedge-380-fixed-and-verified-0194
description: sess382: D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380 CLOSED FIXED AND VERIFIED on 0.19.4 — verified against BOTH the injected and the natural c…
metadata:
  type: project
tags: [mxfs, closed, wedge, obligation, rule6]
---

# sess382 — #380 CLOSED, FIXED AND VERIFIED (0.19.4). open 52 → 51

## The technique that unlocked it: give the cause a switch, then shrink the window

Two sessions had failed to reproduce this. The unlock was not more staring at
code, it was **two test levers**:

1. `mxfs.iflush_fence_fault_ino` — makes a chosen inode's flush take exactly the
   fence shape (error=0, no `flush_seq` stamp). Turns a luck-dependent wedge into
   a ~90 s reproduction (`tests/iflush_fence_wedge.sh`).
2. `mxfs.reldefer_noprogress_ms` — shrinks the release-defer episode's
   **observation window** (60 s → 2 s). The fences, obligations and deferrals
   stay real and unmodified; only how long the test waits changes. This is what
   finally produced a **natural** wedge with no injection at all.

Three attempts to force it with pre-existing knobs gave 1 hit in 3. Building the
levers was far cheaper than waiting.

## The fix (0.17.4 → 0.19.4)

- **(A) One chokepoint** at `xfs_iflush`'s `flush_out`: returning success without
  stamping `flush_seq` while an obligation is open sets `i_mxfs_pub_fenced` —
  one place instead of eleven fences, and it covers future ones.
- **(B) A release-side consumer**: `mxfs_dlm_bast_dwork_fn` drives the reload the
  fence asked for, before the deadline check, bounded at 3, restamping progress
  only on an actual close. Never touches `durable_seq`; keep-guards stay
  authoritative; P177 still reports a dropped change. A bailed adopt still wedges
  — fail-closed preserved, only FALSE firings removed.
- **(C) Both counter runaways**: the drain's gated re-log (`i_mxfs_pipe_relog`)
  no longer bumps `pending_seq` **or** `i_version`/`di_changecount`.

Bug in my own fix, caught by reading the init path: `xfs_inode_alloc` is
`kmem_cache_alloc`, **not** zalloc — new fields must join the explicit reset
block or a recycled inode inherits a previous incarnation's verdict.

## Verification — both causes, paired A/B on one build

**Injected** (0.18.0, lever flipped at runtime): `reldefer_reload=1` → 4 hits,
durable 6→10, P177=1, NO_WEDGE, MOUNT=UP. `=0` → 689 hits, durable stuck at 6,
WEDGE, MOUNT=DOWN. Repeated on 0.18.1/0.18.2/0.19.2.

**Natural** (0.19.4, real workload, no injection, only the window shortened):

| arm | P119 | P176 | P228 | WEDGE | ag_strand_repair | NOMOUNT |
|---|---|---|---|---|---|---|
| pre-fix | 67 | 8 | 10 | **1** | FAIL 240/240, 18/32 | **all 32** |
| fixed | 51 | 0 | 0 | **0** | PASS 81s | none |

Full board at **shipping defaults** green on six builds; FLAKY improved 2 → 1.

## Two claims I had to retract on my own evidence

- The P32E raw-compare contract hole was real and I fixed it — then
  `RAWDIVERGE=0` over 14 firings **disproved** it as the cause. Without that
  probe I'd have credited a no-op patch with a green board.
- I recorded a "deterministic reproducer" after one success; the next two runs
  refuted it. Always score a reproducer over ≥3 runs before writing it down.

## Byproduct worth its own attention

ONE wedge → **all 32 mounts down**, and two nodes left un-reprepable (module
loaded, unmounted, `P265-BASTQ-STATS` counters byte-frozen; needed a VM
destroy/start). Recorded against
`D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474`, which now has a cheap
deterministic harness: disable the three fix levers, set
`reldefer_noprogress_ms=2000`, run dirent_durability + ag_strand_repair.

Rig note: the live libvirt domains for test4/test5 are **test4r/test5r** (clone
replacements from the sess377 host-corruption recovery); the originals are stuck
"in shutdown".
