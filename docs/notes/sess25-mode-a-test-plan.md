# Sess25 Mode A Debugging Test Plan

This doc gives concrete debugging steps for next session to diagnose
Mode A (`xfs_dir_removename rc=-ENOENT`) and bnobt LEFT/RIGHT-FAIL.

## Hypothesis from sess24

Both bugs share a root cause: silent cached state divergence between
nodes.  Cache invalidation triggers Mode A immediately (sess24 bast_poll
self-correct experiment).  The drain/release path needs to be made
trans-aware for Mode A to be safely fixable, then bnobt can be addressed.

## Step 1 — Reproduce Mode A reliably

Sess20-22 saw Mode A intermittently (~10-15% of failed runs, often after
iter 4+).  Sess24 self-correct experiment triggered it at iter 1 100% of
the time when cache invalidation was forced.

**Reliable reproducer**:
1. Reset cluster (full reboot via sysrq if needed).
2. Apply this minimal patch to force cache invalidation on every release:

   ```c
   // In mxfs_dlm_ag_bast_work_fn (xfs_mxfs_dlm.c:1772),
   // change the "skip if !cached" check to always proceed:
   //   if (!pag->pag_dlm_cached) {
   // Replace with comment-out OR scope only to AG=0 for less perturbation:
   //   if (pag_agno(pag) != 0 && !pag->pag_dlm_cached) {
   ```

3. Build, load, run stress.  Mode A should fire iter-1 reliably.

This forced-invalidation gives a fast-feedback loop for testing Mode A
fixes.

## Step 2 — Diagnose the dir block stale path

Add P36-INSTR diagnostic:

1. At `xfs_dir_removename` ENOENT return (libxfs/xfs_dir2.c:1027):
   - dump dir format (sf/block/leaf/node)
   - dump dir size (in_disk_size, in_memory size)
   - dump expected name being looked up

2. At `mxfs_dlm_bast_process` for directory inodes (line 170):
   - dump number of dir block bufs in `pag_bcache` covering this dir's
     allocated extents
   - dump their flags (XBF_DONE, XBF_STALE) and BLI presence

3. At `xfs_iget_cache_hit` after stale-reload (xfs_icache.c):
   - dump first dir entry from fresh dinode

## Step 3 — Test dir-block invalidation fix

Extend `mxfs_dlm_bast_process` for directory inodes (BLOCK/LEAF/NODE
format only — SHORTFORM is in dinode itself, handled by reload_inode):

```c
if (S_ISDIR(vip->i_mode) &&
    ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS) {
    struct xfs_iext_cursor icur;
    struct xfs_bmbt_irec got;
    
    for (xfs_iext_first(&ip->i_df, &icur);
         xfs_iext_get_extent(&ip->i_df, &icur, &got);
         xfs_iext_next(&ip->i_df, &icur)) {
        xfs_daddr_t daddr_start = XFS_FSB_TO_DADDR(mp, got.br_startblock);
        xfs_daddr_t daddr_end = daddr_start +
                                XFS_FSB_TO_BB(mp, got.br_blockcount);
        xfs_daddr_t d;
        int dir_block_bb = XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

        for (d = daddr_start; d < daddr_end; d += dir_block_bb) {
            struct xfs_buf *dbp = NULL;
            int rc = xfs_buf_incore(mp->m_ddev_targp, d,
                                    dir_block_bb, 0, &dbp);
            if (rc == 0 && dbp) {
                xfs_buf_lock(dbp);
                xfs_buf_stale(dbp);
                xfs_buf_unlock(dbp);
                xfs_buf_relse(dbp);
            }
        }
    }
}
```

Notes:
- `mp->m_dir_geo->fsbcount` is the dir block size in fsblocks (typically 1
  for 4k blocks).
- `XFS_FSB_TO_BB` converts fsblocks to disk-block (basic block, 512-byte)
  units, which is what xfs_buf uses for daddr.
- xfs_buf_incore with flags=0 doesn't add a hold, just returns the existing
  cached buf if any.  Need to lock it to stale safely.
- This is similar pattern to `mxfs_dlm_invalidate_ag_meta` but for dir
  blocks.  Test ONLY with diagnostic enabled first to confirm the path
  fires correctly.

Sess22 v0.3.67 attempted similar for inode cluster bufs and reverted due
to "timing instability" — be cautious; test with light P36-INSTR
diagnostic first to confirm the path is being exercised correctly before
committing to it.

## Step 4 — Test trans-aware drain

Mode A surfaces because in-flight transactions reference cached state
that gets invalidated.  Fix candidate: in `mxfs_dlm_ag_bast_work_fn`,
before setting `cached=false`, wait for all in-flight transactions
referencing this pag to commit.

Implementation sketch:
- Add `pag_dlm_active_trans` counter.
- Increment on `mxfs_ag_dlm_lock` acquire, decrement on
  `mxfs_ag_dlm_unlock`.
- bast_work_fn waits for counter==0 before invalidating.

## Step 5 — Validate

Run stress (with ALL diagnostics stripped to avoid timing perturbation)
for 30+ iters.  Look for:
- No Mode A `xfs_dir_removename ENOENT`.
- No bnobt LEFT/RIGHT-FAIL.
- Both nodes alloc/free ranges correctly.

## Tools available

- `tools/caw_verify` (sess24): test cross-init CAW on LIO target.
  ```
  T1: /mnt/mxfs-src/tools/caw_verify write /dev/sda 1000000000 aa
  T2: /mnt/mxfs-src/tools/caw_verify read  /dev/sda 1000000000 aa
  ```
- `tools/chk_mxfs` (sess14+): post-corruption FS validation.
  Useful to compare on-disk btree state vs in-memory views.
- P33-INSTR (in tree): bnobt root buf dump at alloc + LEFT/RIGHT-FAIL.

## Don't repeat

See sess24 don't-repeat list in next-session-prompt.md.

## Expected outcome

If Mode A is fixed, the bnobt LEFT/RIGHT-FAIL should be approachable via
sess24's UDP-BAST-on-claim-empty fix (which previously made things worse
by exposing Mode A — should now be safe).

If Mode A is NOT fixed but worked-around, bnobt fix needs a different
approach (lease-based cached-AG, or other).
