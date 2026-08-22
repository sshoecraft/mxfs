---
name: sess385-agi-publication-stage-landed-and-verification-state
description: sess385: AG-release inode publication stage landed 0.19.17 (3 parts); A/B on one build strong; closing run blocked on a clyde host wedge. Defect stay…
metadata:
  type: project
tags: [agi, unlinked, defect-361, dlm-release, invariant-1, fix-landed, verification]
---

## Build

`0.19.17`, srcversion `EEBC0F69C128B81468B4B47`. Builds clean. **Not yet deployed
to the rig** — clyde wedged before the closing run (see
`sess385-clyde-ext4-jbd2-wedge-shared-lun-on-root-fs`).

Last build actually exercised on the rig: `86580ED23708F236FB1E5FD` (0.19.16),
which carries the same three fixes; 0.19.17 differs ONLY by probe verbosity
(anomaly-gating P85/P86) and by deleting the spent P85-LATEPASS probe.

## What landed, in `mxfs_dlm_ag_bast_work_fn` Phase 2 and `drain_inode_buffers`

**(A) The missing conversion stage (HOLE 2).** `xfs_iflush_cluster(bp)` on any
inode-cluster buffer with a non-empty `b_li_list`, before writing it. Gated by
`mxfs.publish_inodes` (default 1).

**(B) Drain hardening (HOLE 1).** No `_XBF_DELWRI_Q` skip, blocking
`xfs_buf_lock`, pinned/BLI fallthrough, synchronous `xfs_bwrite`.
`_XBF_MXFS_ALLOC_QUEUED` buffers left to `drain_alloc_buflist`.

**(C) Pointee-before-pointer ordering.** alloc + inode drains now run BEFORE the
first `drain_meta_buffers`, with a `blkdev_flush` between, so the AGI is written
after the dinodes it points at.

Full rationale in `.claude/awareness/subsystems/xfs.md` (sess385 section) and in
the ledger entries' `fix_sess385` field.

## Verification state — STRONG BUT INCOMPLETE. Defect remains OPEN.

Controlled A/B on ONE build via the module param, same 4-test chunk, re-prepped
between arms:

| arm | heads | SPLIT | BADHEAD | shutdowns | rsync_paired |
|---|---|---|---|---|---|
| `publish_inodes=0` | 167 | 3 | 4 | 10 | **FAIL 0/32** |
| `publish_inodes=1` | 8 | 0 | 0 | 0 | PASS |

Arm B also hit `Found unrecovered unlinked inode` 3x and recovered cleanly — the
cause exercised and handled. 15 board rows passed on the fixed build with walls
unchanged or better (no RULE 0 cost from the added conversion stage).

**Why it is not closed:** arm B published only 8 heads — far too small a sample
against arm A's 167. RULE 6 wants testing that exercises the cause; 8 does not.

## The closing run (do this first when the host is back)

1. Re-prep, deploy 0.19.17, `dmesg -C` fleet-wide.
2. Repeat the `publish_inodes` A/B, but require the FIXED arm to publish a head
   count comparable to arm A's 167. Require `SPLIT=0` and `BADHEAD=0`.
3. Then a full 28-row board.

## Attribution rule for any residual bad head

- `SPLIT` (`core_nlink==0`) — this node knew the inode was unlinked and failed to
  publish it. **Our bug.**
- `BADHEAD` (`core_nlink==-1`) — the inode was not in this node's cache. Either it
  was already reclaimed (nothing for `xfs_iflush_cluster` to convert), or, more
  likely, this node did not CREATE the head and is merely re-publishing an AGI
  another node left bad. **Attribute before concluding the fix failed.**

## Not a regression — read this before blaming the fix

A run with the fix ON shut down 13 nodes via
`P-NOINO-DRAIN-STUCK` -> `P-NOINO-RELFENCE-WEDGE`. That is
`D-NOINO-RELFENCE-AIL-FREEZE-474`, whose identical signature the ledger already
records from **sess384, before these changes**. In that run P86 reported **0** bad
heads and there were **0** `P217-RENAME` dirty cancels — the #361 signature was
absent entirely. Different defect.
