---
name: sess26-FINAL-root-aba-buffer-stale-bli-fua-skip-and-exact-fix
description: sess26 FINAL: dir_reuse_coherency 2/tcp root = clean prior-incarnation (ABA) dir buf keeps stale attached BLI → mxfs_buf_read_fua SKIPS FUA → serves…
metadata:
  type: project
---

## sess26 (ccloop 8ddb16a2) — ROOT FULLY PROVEN + EXACT NEXT FIX (GPT-consulted). Build C99F988B deployed, cluster rebooted clean. Supersedes earlier sess26 framings.

### THE ROOT (RULE 4, airtight):
dir_reuse_coherency 2/tcp: cold-read stat of node2's files fails. **P26-IGET-FAIL**: dir LOOKUP succeeds (leaf+data find the name) but `xfs_iget(inum)`=-ENOENT — the dirent points to a FREED inode = a PRIOR round's incarnation (consecutive inums 2099073+). The in-core dir DATA buffer (xfs_buf, daddr-keyed) is a **CLEAN prior-incarnation (ABA) buffer that still has a STALE `b_log_item` (BLI) attached**. `mxfs_buf_read_fua` (pal/linux/xfs_buf.c:2077, P91-FUA-SKIP-LOGGED) SKIPS the FUA pierce whenever `b_pin_count>0 || !list_empty(b_li_list) || b_log_item` → keeps the stale in-core buffer, never refreshes → plain-bio reads serve SCST's STALE per-initiator read cache. **The LUN backing store is FRESH** (the dir_merge's raw `mxfs_pal_scsi_read_fua_bdev` read returned the CURRENT inum B; IGET-FAIL→0 with merge on — but merge causes DLM-timeout shutdown rc=-110, unusable).

### WHY the obvious fixes failed (all refuted with evidence):
- Read-side force-evict (clear XBF_DONE in consumer_refresh, already in C99F988B): the BLI stays attached → FUA still skipped → plain-bio → stale.
- `fua_disable=0` alone: no change — the buffer is KEPT (BLI skip), never hits the device.
- The evict's clean branch only does `dbp->b_flags &= ~(XBF_DONE|_XBF_FUA_FRESH)` (SOFT invalidate) — doesn't detach the BLI.

### GPT (RULE 5) verdict: never manually abort a DIRTY/in-AIL BLI (unsafe); for a CLEAN buffer xfs_buf_stale is safe. The dir DLM RELEASE path ALREADY waits `!in_ail && !pinned && data_durable` before unlock (xfs_mxfs_dlm.c:4386+), so the peer's cached ABA buffer IS clean — just keeps a leftover attached BLI. So: detach BLI + stale the CLEAN ABA buffer on the read/acquire evict.

### EXACT NEXT FIX (do this first in sess27):
In `mxfs_dir_evict_data_blocks` (xfs/xfs_mxfs_dlm.c, the `if (!undurable)` CLEAN branch at ~line 2128; `bip = dbp->b_log_item` is in scope, `incarn_aba`/`in_ail` are block-scoped above so RECOMPUTE):
```
bool aba = (dbp->b_mxfs_dir_incarn != 0 && dbp->b_mxfs_dir_incarn != VFS_I(ip)->i_generation);
bool d_in_ail = (bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags));
bool d_dirty  = (bip && test_bit(XFS_LI_DIRTY,  &bip->bli_item.li_flags));
if (aba && !d_in_ail && !d_dirty && !xfs_buf_ispinned(dbp) &&
    !(dbp->b_flags & _XBF_DELWRI_Q) && (dbp->b_flags & XBF_DONE) &&
    list_empty(&dbp->b_li_list)) {
    /* prior-incarnation clean buf w/ leftover BLI: detach BLI + hard-stale so
       the next read cache-misses -> fresh xfs_buf, no BLI -> FUA pierces SCST */
    if (dbp->b_log_item) xfs_buf_item_relse(dbp);   /* pal/linux/xfs_buf_item.c:77, takes struct xfs_buf* */
    xfs_buf_stale(dbp);
    dbp->b_mxfs_dir_incarn = 0; dbp->b_mxfs_dir_gen = 0;
    /* P26-ABA-STALE detector here, capped */
} else {
    dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);   /* existing soft path for non-ABA */
    dbp->b_mxfs_dir_gen = 0;
}
```
Loop already `xfs_buf_relse(dbp)` at line 2200. **MUST run with fua_disable=0** (the post-stale fresh read needs FUA to pierce SCST; default is 1) — test via `MXFS_EXTRA_MODARGS="fua_disable=0"` first; if it passes, decide whether to flip the default (RULE 0 perf check). The consumer-refresh force-evict (already in C99F988B) routes the READ path through this evict, so the cold-read lookup will stale the ABA buf → FUA-refetch fresh → iget succeeds.

### VALIDATION PLAN: `bash tests/reboot_cluster.sh 2; MXFS_EXTRA_MODARGS="fua_disable=0" ./run.sh 2 tcp dir_reuse_coherency`; expect P26-ABA-STALE fires + P26-IGET-FAIL→0 + readdir=200 + no shutdown. Then full `./run.sh 2 tcp` ×3 for 100%. Watch: verify the ABA buffers are actually CLEAN (P26-ABA-STALE fires); if they're dirty/in-AIL instead, the detach is unsafe → pursue GPT's release-side sync-log-force invariant.

### KEEP (proven this session): B5 inact-skip (xfs/xfs_inode.c ~2876, fixes bnobt double-free 0x8 shutdown). consumer_refresh force-evict bypass (xfs_mxfs_dlm.c). mxfs.dir_leaf_rebuild default 0 (rebuild perturbs → test2 short readdir). Detectors P26-IGET-FAIL/RDDIR/LKERR/LKFMT/DSCAN. RISK on the fix: xfs_buf_item_relse must be gated STRICTLY clean.

### REFUTED (don't repeat): leaf-rebuild reliable-fire (perturbs data coherency, test2 readdir=100-117); read-side soft-evict alone; fua_disable=0 alone; dir_merge=1+dir_force_block=1 (DLM timeout rc=-110 CORRUPT_INCORE shutdown at mxfs_dlm_ilock_begin). Marker NOT written.
</body>
