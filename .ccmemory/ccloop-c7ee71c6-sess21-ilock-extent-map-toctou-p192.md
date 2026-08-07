---
name: ccloop-c7ee71c6-sess21-ilock-extent-map-toctou-p192
description: sess21 ROOT+FIX: xfs_ilock_data_map_shared tests xfs_need_iread_extents BEFORE xfs_ilock, but MXFS's DLM acquire hook reloads the inode inside xfs_il…
metadata:
  type: project
---

# sess21 — ILOCK / extent-map TOCTOU (P192)

## Symptom
`soak` @32/caw FAILs on `dmesg_hits=1` (errs=0, ops=1664). The hit:

    WARNING: CPU:1 PID:29246 at include/linux/rwsem.h:85
             xfs_assert_ilocked+0x9b/0xc0 [mxfs]      (RSI=4 = XFS_ILOCK_EXCL)
    openat -> xfs_vn_lookup -> xfs_lookup -> xfs_dir_lookup
      -> xfs_dir_lookup_args -> xfs_dir2_format
         -> xfs_bmap_last_offset -> xfs_bmap_last_extent -> xfs_iread_extents

Fired on **3 of the 4 soak nodes** at ~1900-2135 s uptime. Needs an aged
cluster — a 30 s soak on a fresh prep does NOT reproduce it.

## Root
`xfs_ilock_data_map_shared()` / `xfs_ilock_attr_map_shared()` (xfs/xfs_inode.c)
pick SHARED-vs-EXCL by testing `xfs_need_iread_extents()` **before** calling
`xfs_ilock()`.

Upstream this is sound: nothing can unload a fork without already holding
ILOCK_EXCL, so the predicate cannot change between test and use.

**MXFS breaks that invariant.** `xfs_ilock()` recurses into the MXFS DLM
acquire hook, which can run `mxfs_dlm_reload_inode()` to adopt a peer-committed
on-disk image — resetting the fork. The sess115 comment in `xfs_dir_lookup`
(xfs/libxfs/xfs_dir2.c ~line 727) already documents this exact recursion for a
different consequence ("can RELOAD dp from a peer-committed on-disk image").

So the predicate is stale by the time `xfs_ilock` returns. This is NOT a rare
cross-CPU race — the very call we make next is what invalidates it. We then
proceed into an EXCL-required path holding only SHARED, and two SHARED holders
can race to populate the same in-core extent map.

`xfs_iread_extents` early-returns when `!xfs_need_iread_extents(ifp)`, so the
assertion is only reachable when the predicate is TRUE at that point — which is
why re-testing the same predicate right after the acquire catches it.

## Fix (v0.11.164, srcver 59EC1178CB76EB393B80942)
`mxfs_ilock_map_recheck(ip, ifp, lock_mode, which)` in xfs/xfs_inode.c, called
at the end of BOTH map_shared helpers: re-evaluate `xfs_need_iread_extents()`
after the acquire; if it is now true and we only got SHARED, `xfs_iunlock` and
retake at `XFS_ILOCK_EXCL` (preserving the `XFS_ILOCK_MXFS_PRIREAD` tag).
EXCL-when-unneeded is heavier but never incorrect, so ONE retry suffices — no
unbounded loop. Lever: `mxfs.ilock_map_recheck=0` for A/B.

## Validation (causal, attributable)
Full 32/caw sweep, all 32 nodes:
- `P192-ILOCK-MAP-RACE` fires **34x** — `fmt=3` (XFS_DINODE_FMT_BTREE),
  `nextents=24/28/58`, comm=dd/md5sum. The reload really does hand back a
  BTREE fork with `if_height==0`.
- `xfs_assert_ilocked`: **present on 3 of 4 nodes -> 0**
- zero WARNING/BUG/Oops cluster-wide; **32/caw 20/20 PASS**
Full 32/tcp sweep: P192 fires **16x**, assertion 0 — transport-independent, as
the mechanism predicts. **32/tcp 20/20 PASS**.

## Watch for this pattern elsewhere
ANY upstream XFS "test a fork/inode predicate, then take ILOCK, then act on the
earlier answer" is unsound in MXFS, because the acquire itself can reload. This
is a general class, not a one-off. Grep for predicates evaluated before
`xfs_ilock*` and used after.
