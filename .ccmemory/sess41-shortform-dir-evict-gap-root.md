---
name: sess41-shortform-dir-evict-gap-root
description: sess41 ROOT of 16-node posix barrier-visibility blocker: EVICT-RING-DIRMOD doesn't cover SHORTFORM dirs. Fix = arm mxfs_dlm_reload_inode for shortfor…
metadata:
  type: project
---

# sess41 — ROOT CAUSE of the 16-node posix_semantics barrier-visibility blocker

Builds on [[sess41-ccloop-agi-reentrancy-deadlock-fixed]]. AGI deadlock already FIXED (build E25DD67F, KEEP). This is the SECOND, remaining blocker (posix_semantics_multi16 > 600s).

## ROOT (proven by code reading + symptom match)
**`EVICT-RING-DIRMOD` does NOT cover SHORTFORM directories.**
- Consumer `mxfs_dlm_evict_inode_cb` (xfs/xfs_mxfs_dlm.c:8335): on peer DIR_MODIFY it only does `ip->i_dlm_dir_gen++`, which (per its own comment) makes "the next readdir's **xfs_da_read_buf** invalidate stale cached dir DATA/LEAF blocks." That hook fires ONLY for block/leaf dirs.
- `xfs_readdir` (xfs/xfs_dir2_readdir.c:511): for `XFS_DINODE_FMT_LOCAL` (shortform) it `return xfs_dir2_sf_getdents()` reading inline `dp->i_df.if_data` BEFORE taking `xfs_ilock_data_map_shared` — NO ILOCK/DLM reacquire, NEVER calls xfs_da_read_buf. So the gen bump is a no-op for shortform; the inode is never reloaded.
- Guard `ip->i_dlm_dir_gen != 0` also skips shortform dirs only ever read single-node.

## Why the symptom matches exactly
- Barrier dir `.mxfs_barriers/<name>/` (~16 short "nodeN" entries) = **shortform** → peer's added entry invisible to other nodes' readdir → barrier's 120s soft timeout (intermittent: depends on whether an unrelated inode-DLM reacquire/BAST reloads it within 120s).
- Data dir `.mxfs_test/concurrent_touch/` (1600 entries) = **block/leaf** → covered → count always correct.
- Data-correct / barrier-stale split is the fingerprint.

## The reload primitive EXISTS and is proven
`mxfs_dlm_reload_inode(ip, ftype)` (called at xfs/xfs_inode.c:875,1010 on the iget lookup path under XFS_ISTALE_CAW) does an IN-PLACE reload that invalidates the inode cluster buffer + dir DATA blocks and **repopulates i_generation AND the dir-fork from disk** — comment: "The next dir read then sees the peer's current entries." This is EXACTLY what a stale shortform dir needs. It's currently triggered only by the evict ring's **INODE_FREE** branch (sets XFS_ISTALE_CAW) via the **lookup** path — NOT by DIR_MODIFY, and NOT on readdir (readdir uses an already-cached, held inode; never re-igets).

## FIX (implement next, RULE 4)
Two coordinated changes:
1. **Evict cb DIR_MODIFY branch** (xfs_mxfs_dlm.c:8335): for a live cached **dir** inode, in ADDITION to `i_dlm_dir_gen++`, set a per-inode "shortform dir reload needed" flag (cb may take only spinlocks — no I/O). Reuse `i_dlm_stale`/a new bit; drop the `i_dlm_dir_gen != 0` precondition for the shortform case.
2. **xfs_readdir** (xfs_dir2_readdir.c, the `if (if_format == LOCAL)` branch): in multi-node mode, if the reload flag is set, call `mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN)` (needs the right lock — readdir holds IOLOCK_SHARED; reload wants ILOCK; verify locking, mirror the lookup-path call which holds ILOCK) BEFORE `xfs_dir2_sf_getdents`, clear the flag on success. This refreshes inline entries so getdents sees the peer's add.

CAUTION: do NOT poll the disk on every getdents — gate on the peer-set flag only (per-readdir CAW polls regressed before: sess38/91 d_revalidate barrier timeouts). The flag makes it event-driven, not polled.

## Verify
Run `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 16 --test test_concurrent_touch --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared --no-color` 4-5× (INTERMITTENT) — each must finish <120s, zero barrier timeouts. Then cross_visibility, dir_stress, then full posix_semantics(16). `tests/criteria/barrier_vis_repro.sh` does NOT reproduce (always 2-3s) — use the real test. `barrier_wait` now logs `present=[...]` on timeout (sess41 diag in tests/lib/cluster.sh). Clean slate: `scripts/cluster_reset_n.sh 16` then `tests/reset4.sh 16`.
