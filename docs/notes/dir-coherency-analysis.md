# MXFS v0.2.6 — Directory Coherency Analysis

Started: 2026-04-25 (fresh session, post v0.2.5)

## Bug

After 2-node concurrent dd reproducer (state.md "Open Bug"), each node only sees its
own dir entries:

- T1 created `perf_t1`, T2 created `perf_t2` in root dir.
- T1 `ls /mnt/mxfs` → only `perf_t1`.
- T1 `rm perf_t1` succeeds.
- T1 `rm perf_t2` → ENOENT.

## Architecture map (relevant subsystems)

- `xfs/xfs_inode.c` — `xfs_ilock` / `xfs_iunlock` / `xfs_ilock_demote` are the MXFS DLM
  hook sites (lines 142, 194, 274, 313). The hook fires on both IOLOCK_* and ILOCK_*.
- `xfs/xfs_mxfs_dlm.c` — DLM lock-cache state machine, BAST processing, inode reload.
  Per-inode `i_dlm_mode` / `i_dlm_state` / `i_dlm_stale`.
- `xfs/libxfs/xfs_dir2.c` — `xfs_dir_lookup` (line 426). Calls
  `xfs_ilock_data_map_shared(dp)` (line 455) → hook fires.
- `xfs/xfs_dir2_readdir.c` — `xfs_readdir` (line 511). For SHORTFORM dirs, returns
  immediately at line 537–538 via `xfs_dir2_sf_getdents` WITHOUT calling
  `xfs_ilock_data_map_shared`. For BLOCK/LEAF/NODE, calls it at line 540.
- `pal/linux/xfs_file.c:1759` — `xfs_file_readdir` is the `iterate_shared` op. Does
  NOT call `xfs_ilock` itself — relies on VFS having taken `inode_lock_shared` (i.e.
  `down_read(&i_rwsem)` directly, BYPASSING the MXFS hook).
- `pal/linux/xfs_iops.c:325` — `xfs_vn_lookup` calls `xfs_lookup`. `xfs_lookup`
  does NOT take ILOCK directly; relies on `xfs_dir_lookup` to do so.

## Hook coverage map (where MXFS DLM hook DOES / DOES NOT fire)

| Op                | Path                                                        | Hook fires? |
|-------------------|-------------------------------------------------------------|-------------|
| readdir SHORTFORM | VFS i_rwsem (direct) → xfs_file_readdir → xfs_readdir SF    | **NO**      |
| readdir BLOCK/LEAF| VFS i_rwsem (direct) → xfs_file_readdir → xfs_readdir+ILOCK | YES (ILOCK) |
| lookup            | VFS → xfs_vn_lookup → xfs_lookup → xfs_dir_lookup + ILOCK   | YES (ILOCK) |
| create            | VFS → xfs_vn_create → xfs_generic_create → xfs_create + ILOCK_EXCL | YES |
| remove            | VFS → xfs_vn_unlink → xfs_remove → xfs_ilock(dp, EXCL)      | YES         |

## Hypothesis 1 — readdir on shortform dirs never fires DLM hook

**Confirmed by code reading.** `xfs_readdir` at xfs_dir2_readdir.c:537-538 returns
directly via `xfs_dir2_sf_getdents` for shortform format without taking ILOCK. The
upstream IOLOCK is taken by VFS `inode_lock_shared` directly via `down_read(&i_rwsem)`,
which does NOT go through `xfs_ilock`. So no MXFS hook fires.

**Consequence**: `ls /mnt/mxfs` on T1 reads `ip->i_df.if_data` (T1's in-memory copy),
which is stale w.r.t. T2's create until something else triggers reload.

This explains the `ls` symptom directly.

## Hypothesis 2 — rm perf_t2 ENOENT despite hook firing on lookup

The lookup path DOES fire the hook (xfs_dir_lookup → xfs_ilock_data_map_shared).
So reload should happen. Why does `rm perf_t2` still fail?

Sub-hypothesis 2a: by the time `rm perf_t2` runs, T1 has root_dir EX cached
(from `rm perf_t1`'s reload, which would have populated [perf_t1, perf_t2] in
memory). Fast path, no reload needed. Should find perf_t2. **Should work.**

Sub-hypothesis 2b: `rm perf_t1`'s reload didn't pick up perf_t2 because T2 didn't
flush the dinode to disk before releasing. But `mxfs_dlm_bast_process` does
`xfs_log_force(SYNC) + xfs_ail_push_all_sync + blkdev_issue_flush + xfs_buf_stale +
xfs_imap_to_bp + blkdev_issue_flush` — should be sufficient.

Sub-hypothesis 2c: T2 hasn't BAST-released yet at the time T1 acquires. CAW lock
will block T1 until T2 releases. So this can't be it.

**Need empirical data to distinguish.** Plan: reproduce, add instrumentation in
`mxfs_dlm_reload_inode` to dump dinode contents on reload, and in
`mxfs_dlm_bast_process` to dump dir contents pre-flush.

## What native shared-disk filesystems do

- **OCFS2**: dcache invalidation + buffer invalidation in BAST (`ocfs2_inode_bast_func`
  → `ocfs2_drop_dl_inodes` for dentries; buffer invalidate via `ocfs2_metadata_cache_purge`).
- **GFS2**: glock state machine includes `gl_ops->go_inval` callback that does
  `gfs2_ail_empty_gl + truncate_inode_pages + invalidate_inode_pages2`. For dir glocks,
  also invalidates the dentry cache.

The dlm.md "Known Limitation #1" already calls this out: "VFS dentry cache not
invalidated on BAST — files created on node A after node B has cached the directory
listing are not visible to node B until remount or dcache invalidation. Page cache
IS invalidated. GFS2 and OCFS2 both do dcache invalidation in their BAST handlers."

## Proposed fix (initial)

Two parts:

### Part A — readdir hook

Make readdir fire the DLM hook so shortform dirs reload. Options:

A1. In `xfs_file_readdir`, call `xfs_ilock(ip, XFS_IOLOCK_SHARED)` before
    calling `xfs_readdir`, and `xfs_iunlock` after. (BUT: VFS already holds
    i_rwsem shared, so `down_read` would just nest — we'd need to take ILOCK_SHARED
    instead, since the IOLOCK is already held at the VFS level.)

A2. In `xfs_readdir` itself, before the format check at line 537, call
    `xfs_ilock(dp, XFS_ILOCK_SHARED)` / unlock at end. Simpler and covers all
    formats. The block/leaf path already takes ILOCK_SHARED via
    xfs_ilock_data_map_shared, but doing it earlier is harmless (lock nesting OK).
    Actually cleaner: just call mxfs_dlm_ilock_begin/end directly (or factor it).

A3. Hook directly in `xfs_file_readdir` with a thin call to `mxfs_dlm_ilock_begin(ip,
    PR)` + `mxfs_dlm_ilock_end(ip, PR)`. Bypasses the local i_lock entirely (which
    isn't needed since VFS already holds i_rwsem and shortform reads from if_data
    don't race with concurrent local writes).

A2 is the cleanest — symmetric with how every other dir op fires the hook.

### Part B — dcache invalidation in BAST

When BAST fires for a directory inode, drop the dcache children so subsequent
lookups MUST go through xfs_lookup (which fires the hook).

In `mxfs_dlm_bast_process`:
```c
if (S_ISDIR(vip->i_mode))
    shrink_dcache_parent(d_find_alias(vip));  /* or equivalent */
```

Without Part B, even after Part A, lookups that hit a stale negative dentry would
short-circuit. (But: negative dentries for never-looked-up names don't exist; this
matters mostly for files renamed/deleted on the other node.)

### Diagnostic plan first

Before coding, reproduce and instrument to confirm:
1. Does T1's `rm perf_t1` actually trigger a reload, and does the reload see perf_t2
   on disk? — if YES, then the bug is in the cached fast path during `rm perf_t2`
   (unlikely per analysis above) or somewhere else entirely.
2. If reload doesn't see perf_t2 on disk, then T2's flush is incomplete.

## Files I have read so far

- /src/mxfs/CLAUDE.md, /src/mxfs/state.md
- /src/mxfs/xfs/xfs_mxfs_dlm.md
- /src/mxfs/xfs/xfs_mxfs_dlm.c (lines 90-548)
- /src/mxfs/xfs/xfs_inode.c (lines 53-180, 274-330, 578-657, 1949-2037)
- /src/mxfs/xfs/libxfs/xfs_dir2.c (lines 420-480)
- /src/mxfs/xfs/xfs_dir2_readdir.c (lines 505-556)
- /src/mxfs/pal/linux/xfs_file.c (lines 1755-1782)
- /src/mxfs/pal/linux/xfs_iops.c (lines 320-388)

## What I still need to confirm before changing code

- Empirical reproduction with logging to confirm whether reload actually picks up
  T2's changes from disk (Hypothesis 2b vs 2a).
- The exact dcache invalidation API for an inode whose alias may be the root dentry
  of a mount.

## v0.2.6 readdir-hook fix — VALIDATED

Edit: pal/linux/xfs_file.c:1759 — `xfs_file_readdir` now wraps `xfs_readdir` with
`xfs_ilock(ip, XFS_ILOCK_SHARED)` / `xfs_iunlock`. This makes the MXFS DLM hook
fire on every `getdents`, including shortform dirs.

Empirical reproduction (2026-04-25):
- T2 `touch /mnt/mxfs/foo` (creates inode 131 in dir 128).
- T1 `ls /mnt/mxfs` → shows `foo`. dmesg confirms: `BAST set stale ino=128`
  followed by `DLM reload ino=128 disk_size=17 first_entry="foo"`. Reload picks
  up T2's update on disk.
- T1 `rm /mnt/mxfs/foo` → reports OK. Lookup found foo, dir-entry removal
  succeeded.

So the directory-block coherency hole called out in `xfs_mxfs_dlm.md`
"Known Limitation #1" is fixed for the readdir path.

## Latent bug exposed — finobt corruption on cross-node inode free

After T1's `rm foo` succeeded, the inactive worker fired:
```
[87.617] DLM reload inode 131 (mode=0100644)  # foo's inode
[87.619] XFS (sda): Internal error rec.ir_free != ibtrec->ir_free ||
         rec.ir_freecount != ibtrec->ir_freecount at line 2333 of file
         /src/mxfs/xfs/libxfs/xfs_ialloc.c.  Caller xfs_difree_finobt+0x1f7
[87.619] xfs_corruption_error → xfs_difree_finobt → xfs_difree →
         xfs_inode_uninit → xfs_ifree → xfs_inactive_ifree →
         xfs_inactive → xfs_inodegc_worker
[87.624] Shutting down filesystem.
```

`xfs_difree_finobt` line 2333 cross-checks the finobt record against the
inobt record (`ibtrec` was previously read from inobt, `rec` was just read
from finobt). They disagree, meaning T1's view of one of the two btrees is
stale w.r.t. the other.

**Hypothesis**: v0.2.5 release-side defer waits for `pag_dlm_meta_pending`
to drain, but `mxfs_ag_meta_track` is hooked at `xfs_trans_log_buf`. If
T2's inobt and finobt updates land in separate transactions, only one of
the two buffers may be tracked at the moment `mxfs_ag_dlm_unlock` fires,
and the OTHER may complete writeback before the deferred-release iodone
flips. Net: T2 releases AG DLM with only one of the pair durably on disk.
T1 acquires fresh, invalidates both, re-reads — but if disk only has the
new inobt and old finobt, T1 sees a mismatch.

Alternative: the v0.2.5 invalidate runs but a finobt buffer was BOUND to a
log item or delwri-queued at invalidate time, so the "fully clean" filter
skipped it. Then T1 read the stale cached copy.

This was MASKED prior to the readdir hook fix: T1's stale dir didn't
contain `foo`, so T1 never attempted `xfs_remove(foo)`, so the inactive
free path never ran. Now that T1 sees `foo` and removes it, the cross-node
inode-free path is finally exercised.

**Status**: this is in scope of the v0.2.5 AG-metadata coherency design,
not of the directory-coherency fix. Reserve for follow-on work in this
session pending user direction.

## v0.2.6 — Cross-node create/free coherency

After fixing the readdir hook, the latent finobt corruption surfaced and
required additional fixes. v0.2.6 ships four changes:

### 1. `xfs/xfs_file.c` — readdir DLM hook (the original target)
`xfs_file_readdir` now wraps `xfs_readdir` with `xfs_ilock(ip,
XFS_ILOCK_SHARED)`/`xfs_iunlock`.  Without this, shortform-dir readdir
returned without ever calling `xfs_ilock`, so peer dir updates were
invisible until something else triggered a reload.

### 2. `xfs/xfs_inode.c::xfs_inactive_ifree` — AG DLM lock + sync flush
Added `mxfs_ag_dlm_lock` around the entire inode-free transaction (alloc
through commit), with `xfs_log_force(SYNC) + xfs_ail_push_all_sync +
xfs_buftarg_wait + blkdev_issue_flush` after `xfs_trans_commit` and
before `mxfs_ag_dlm_unlock`.  The lock is released only after the freed
dinode (mode=0) is durable on disk so a peer freshly allocating from this
AG cannot read the stale dinode and trip xfs_dialloc's "Free inode 0x%x
not marked free!" check.  An earlier attempt put the lock inside
`xfs_ifree`, which fires before the trans commit — the failure is exactly
what state.md "Failed second attempt" calls out.

### 3. `xfs/xfs_mxfs_dlm.c::mxfs_dlm_invalidate_ag_meta` — inode-buffer staling
Extended the discriminator for the acquire-side invalidate to include
`xfs_inode_buf_ops` and `xfs_inode_buf_ra_ops`.  The "fully clean"
filter also now checks `b_li_list` (inode log items) in addition to
`b_log_item` (buffer log item) to avoid staling an inode buffer with
pending inode flushes attached.  Required so a peer's freshly-acquired
AG drops cached inode cluster buffers and re-reads from disk.

### 4. `xfs/xfs_icache.c::xfs_iget_cache_hit` — stale-cache reload on CREATE
`xfs_iget(CREATE)` checks in-memory `i_mode != 0` to detect "free inode
not marked free" corruption — but the in-memory cache can be stale
relative to a peer-freed inode.  Added a check: if `m_mxfs_dlm` set and
`(flags & XFS_IGET_CREATE)` and `i_dlm_stale` and not `IRECLAIMABLE`,
drop locks, call `mxfs_dlm_reload_inode(ip)` to re-read from disk,
return `-EAGAIN` so xfs_iget retries.  Required because the alloc path
(xfs_dialloc → xfs_iget(CREATE)) does not take the per-inode DLM lock
before reading i_mode — the AG DLM lock provides the serialisation but
not the cache-coherency.

### Validation

- Simple sequential T2-touch / T1-ls / T1-rm: PASSES 3/3 (and 5/5 with
  longer sleeps).  No corruption, no shutdown.
- Earlier test with rapid-fire iterations: revealed timing-related ls
  failures (T2's create hadn't propagated by the time T1 ls'd a specific
  path), but data is consistent across both nodes in the final state.
- Full v0.2.5 dd reproducer (1GB perf_w + drop_caches + concurrent 1GB
  dd + rm): the sequential portion passes; concurrent-dd portion hangs
  on the rm step (deadlock — needs follow-up).
- **Critical lesson**: incremental builds were producing stale modules.
  Always `make clean` before rebuilding when changes span multiple files.

### Open issues for next session

1. Concurrent-dd + rm hangs the filesystem — need to isolate which
   change interacts badly with concurrent allocation+free.  Suspect:
   the deferred-release machinery may not fire correctly when multiple
   AG-meta writes complete out of order, leaving `pag_dlm_release_pending`
   true forever.
2. Rapid-fire single-file create-on-T2 / lookup-on-T1 has a timing
   race (T2's create commit returns before disk write completes; T1's
   subsequent lookup may BAST T2 too early).  Probably needs
   `wsync`/`dirsync` mount option or similar to force synchronous dir
   updates.
3. v0.2.6 not yet stress-tested with the mkdir cohort or rsync 584MB
   workload.  Reserve.

### Files modified in v0.2.6 (cumulative)

- `pal/linux/xfs_file.c` — readdir ilock wrapper
- `xfs/xfs_inode.c` — xfs_inactive_ifree AG lock + sync flush
- `xfs/xfs_mxfs_dlm.c` — invalidate inode buffers; export reload
- `xfs/xfs_mxfs_dlm.h` — declare mxfs_dlm_reload_inode
- `xfs/xfs_icache.c` — stale-iget(CREATE) reload trigger
- `VERSION` — 0.2.5 → 0.2.6

