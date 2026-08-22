---
name: sess385-publication-enforcement-and-agi-lock-order-trap
description: sess385 Part D: AG-unlock publication enforcement (verify/repair/re-verify) landed 0.19.20; plus the AGI-buffer lock-order trap it nearly introduced.
metadata:
  type: project
tags: [agi, unlinked, defect-361, dlm-release, invariant-1, lock-order, fix-landed]
---

## Why Part D exists

The sess385 conversion stage uses `xfs_iflush_cluster`, which is **non-blocking
by design** (`xfs_ilock_nowait`) — that is precisely what keeps it out of the
whole-AG `ail_push` deadlock that killed the two previous attempts. The cost:
an inode whose ILOCK is held by another thread is skipped, and if it is still
skipped when the pass-until-quiescent loop hits its cap, the old code would
unlock and publish a split anyway.

Architectural Invariant 1 and the RULE-5 ruling both say the same thing: a drain
that did not complete must **never** be followed by an on-disk unlock. A timeout
may diagnose, shut down or fence — it may not silently release.

## What landed (0.19.20, sv 50B07EF2D616706B3733F34)

`mxfs_p86_agi_unlinked_publish_audit()`, called immediately before
`mxfs_v5_dlm_ag_unlock`, is now **verify → repair → re-verify**:

| observed | classification | action |
|---|---|---|
| home dinode `nlink == 0` | `joint_ok` | none |
| LINKED **and** in our cache with `i_nlink == 0` | **SPLIT** — ours | targeted repair, up to `mxfs.publish_retries` (default 3) |
| LINKED and **not** in our cache | **BADHEAD** | report only — no authority |
| SPLIT survives repair | violation | `P86-AGI-UNLINKED-PUBLISH`; shutdown iff `mxfs.publish_refuse_unlock=1` |

Repair, per inode: `xfs_log_force(SYNC)` → `xfs_imap` → `xfs_buf_incore`
(blocking lock, **INCORE-only** — reading the medium here would install a stale
image over nothing) → `xfs_iflush_cluster` → `xfs_bwrite` → `blkdev_flush` →
re-FUA-read. Success logs `P87-PUBLISH-REPAIRED`.

`mxfs.publish_refuse_unlock` **defaults to 0 (warn only)** on purpose. Shipping
an unmeasured cluster-wide shutdown path is a RULE 4 violation, and #474 is the
standing demonstration of what an uncontained shutdown costs. Measure the repair
rate first, then flip it.

## The lock-order trap — caught in self-review, before any rig run

The first cut ran the repair **while still holding the AGI buffer locked**. That
self-deadlocks the release worker, for two independent reasons:

1. `xfs_imap(pag, NULL, ino, &imap, 0)` looks like pure arithmetic, and is —
   *but only* when `blocks_per_cluster == 1` or `inoalign_mask != 0`. Otherwise
   it falls through to `xfs_imap_lookup`, an **inobt btree read that reads the
   AGI**. Do not assume `flags=0` means "no I/O": read
   `xfs_ialloc.c:xfs_imap()` to the end before believing it.
2. `xfs_log_force` can drive an AIL push that also wants the AGI buffer.

Fix: **snapshot all 64 `agi_unlinked[]` heads into a local array and drop the
AGI buffer before doing anything else.** Safe because we still hold the AG DLM
EX and `pag_dlm_demoting` is set, so neither a peer nor a local acquirer can
change the list underneath us.

**Rule for anyone extending this audit: keep every step outside the AGI buffer
lock.**

## What to measure next, and how to read it

With `publish_refuse_unlock=0`, collect `P87-PUBLISH-REPAIRED` vs surviving
`P86-AGI-UNLINKED-PUBLISH` over a run that publishes many heads (arm A reached
167 in one chunk).

- Repair converts essentially all SPLITs → flip `publish_refuse_unlock=1`, re-run.
- A stubborn residue → those are inodes whose ILOCK is held across a blocking
  DLM wait. That is exactly the **a2 arm of `D-NOINO-RELFENCE-AIL-FREEZE-474`**
  ("no blocking remote DLM acquire/CAW poll while holding ILOCK"). The two
  defects share that root and should be fixed together.
- **BADHEAD is not repairable by us by construction.** A non-zero BADHEAD count
  means another node published a split, so the fix must be deployed fleet-wide
  before BADHEAD can be expected to reach zero. Do not read BADHEAD > 0 as this
  node's fix failing.
