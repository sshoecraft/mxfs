---
name: GFS2 cache-coherency contract — reference pattern for Mode A and AIL deadlock
description: GFS2's per-glock release/invalidate pattern (inode_go_sync + inode_go_inval + gfs2_ail_empty_gl) is a useful reference for MXFS's Mode A and the per-AG AIL drain problem. Pattern is independent of DLM transport choice.
type: project
originSessionId: 577f8f30-2496-458a-8b8e-8c2966f4ae36
---
The DLM transport (CAW vs TCP) and the cache-coherency contract on lock
release/demote are independent axes. GFS2 is a good reference for the latter
even though MXFS uses a different (CAW) transport for scaling reasons.

**Why:** Sess20-27 keep finding "new" coherency bugs (Mode A, bnobt LEFT/RIGHT-
FAIL, single→multi stale i_dlm_mode, AIL deadlock at 5×512MB). Pattern
suggests symptom-chasing without a written-down contract. GFS2 has had 20+
years to harden its contract; reading it makes MXFS's gaps visible.

**How to apply:** When debugging a Mode A or coherency bug, audit MXFS's
release/demote path against this GFS2 reference (in ~/src/linux/fs/gfs2/):

`inode_go_sync` (glops.c ~line 303) — runs BEFORE releasing/demoting glock to peer:
  1. inode_dio_wait                    — drain direct I/O
  2. gfs2_log_flush(... NORMAL ...)    — flush journal
  3. filemap_fdatawrite(metamapping)   — write metadata pages
  4. filemap_fdatawrite + fdatawait    — write+wait data pages (for regular files)
  5. gfs2_inode_metasync(gl)           — sync metadata buffers
  6. gfs2_ail_empty_gl(gl)             — PER-GLOCK AIL drain (KEY)

`inode_go_inval` (glops.c ~line 358) — runs on demote (peer now owns):
  1. truncate_inode_pages(mapping, 0)         — drop ALL cached pages
  2. set_bit(GLF_INSTANTIATE_NEEDED)          — force reload from disk
  3. gfs2_dir_hash_inval(ip)                  — drop directory hash cache
  4. forget_all_cached_acls / sec_invalidate  — drop ACL/security caches

Two specific MXFS gaps this reference exposes:

1. **AIL granularity (Bug 3 — sess27 5×512MB deadlock).** MXFS uses
   `xfs_ail_push_all_sync` (whole AIL) in `mxfs_dlm_ag_bast_work_fn`. GFS2 uses
   `gfs2_ail_empty_gl(gl)` (per-glock). The whole-AIL primitive deadlocks
   under stress because items from OTHER glocks block the drain. The fix is
   per-AG drain, not bounded-timeout (sess27 already proved bounded-timeout
   breaks correctness). Sess27 left an unused `xfs_ail_push_all_sync_timed`
   stub in xfs_trans_ail.c — that's the wrong shape; the right shape is
   `xfs_ail_push_ag_sync(ag)` filtering by AG/inode.

2. **Cache invalidation on demote (Mode A family).** Sess25's "single→multi
   transition leaves stale i_dlm_mode + pag_dlm_cached" is the mirror image of
   GFS2's `GLF_INSTANTIATE_NEEDED` machinery. GFS2 throws the cache out on
   demote and forces reload on next acquire; MXFS tries to track validity via
   i_dlm_mode and that tracking has bugs. The simpler/safer pattern is
   throw-and-reload.

NOT a model for MXFS:
- GFS2's transport (kernel TCP DLM via fs/dlm/lowcomms.c). MXFS targets >24-
  node clusters where TCP saturates; CAW stays primary. See
  project_caw_is_load_bearing.md.
