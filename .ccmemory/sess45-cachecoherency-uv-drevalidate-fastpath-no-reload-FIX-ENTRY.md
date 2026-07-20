---
name: sess45-cachecoherency-uv-drevalidate-fastpath-no-reload-FIX-ENTRY
description: sess45 FIX ENTRY for cache_coherency uv: mxfs_drevalidate (xfs_mxfs_dentry.c) IS active + takes xfs_ilock(dp,SHARED)+xfs_dir_lookup, but the SHARED a…
metadata:
  type: project
---

## sess45 — cache_coherency uv: precise fix entry point (full root chain)

Root chain (all PROVEN this session): node1 dir-block xfs_buf cache-stale (drop_caches fixes) →
b_mxfs_dir_gen invalidation inert because i_dlm_dir_gen never bumps for node1's lookups → bump only
happens on SLOW-PATH dir DLM re-acquire (xfs_mxfs_dlm.c:9294).

### NEW: d_revalidate IS already enabled but INSUFFICIENT.
`sb->s_d_op = &mxfs_dentry_operations` is ACTIVE (pal/linux/xfs_super.c:2303; the "sess38 DISABLED"
note is superseded by a later "sess45 RE-ENABLED" — but that comment's "node-affine cheap gating" is
STALE: the actual `mxfs_drevalidate` (xfs/xfs_mxfs_dentry.c:42) does the FULL revalidate for every
multi-node dentry). It takes `xfs_ilock(dp, XFS_ILOCK_SHARED)` then `xfs_dir_lookup` and returns 0
(drop dentry) iff the name no longer resolves. For uv, node1's positive dentry for node2_file21 is
revalidated, BUT `xfs_dir_lookup` reads node1's STALE cached `$D` dir DATA block (still lists the
file) → resolves → returns 1 (valid) → `test -e` finds it → FAIL.

### WHY the SHARED acquire doesn't refresh: node1 read `$D` during the pre-delete `ls` (uv check 68),
caching a DLM grant (PR) on `$D`. node2's EX (deletes) SHOULD BAST that PR so node1's next SHARED
acquire is SLOW-PATH (reload + i_dlm_dir_gen++ + dir-block invalidate). It doesn't: node1's
xfs_ilock(SHARED) in d_revalidate FAST-PATHS on the still-cached grant → no reload. Either node2's EX
isn't BAST-downgrading node1's PR on `$D`, or node1 re-grants fast without reloading.

### FIX OPTIONS (next session, RULE-4 instrument first; watch RULE-0 perf vs tcp_dlm_scaling):
1. In `mxfs_drevalidate`, for a POSITIVE dentry in a multi-node dir whose parent is peer-owned
   (or always, multi-node), FORCE a coherent dir-block refresh before/at the lookup: bump
   dp->i_dlm_dir_gen (so xfs_da_read_buf invalidates the cached `$D` data block and FUA-re-reads),
   OR explicitly xfs_buf_stale + clear XBF_DONE on `$D`'s cached dir DATA blocks. This is the
   drop_caches-equivalent, scoped to the one dir. Cost = a dir-block re-read per revalidate of a
   peer file (the sess38 perf worry — but it's per cached peer-dentry lookup, and TCP reads are
   coherent under fua_disable, so likely acceptable; MEASURE tcp_dlm_scaling).
2. Fix the DLM so node2's EX on a dir BAST-downgrades node1's cached PR → node1's next SHARED is
   slow-path (already bumps gen + reloads). Cleaner but core-DLM-state work (instrument the BAST
   delivery + node1's grant state for `$D` during the deletes: P-DIRBAST / dlm grant trace).
Likely also fixes dir_reuse leaf-hash (same dir-read-staleness class). VERIFY with
`./run.sh 2 tcp cache_coherency` (node1 must stop seeing node2_file21..30). Keep
[[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]]; suite at 14/17
([[sess45-MILESTONE-full-suite-14of17-three-remaining]]). [[sess45-cachecoherency-uv-evictring-dedup-and-async-heartbeat-gap]]</body>
