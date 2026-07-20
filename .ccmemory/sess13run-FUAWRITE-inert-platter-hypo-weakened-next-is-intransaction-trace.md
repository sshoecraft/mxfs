---
name: sess13run-FUAWRITE-inert-platter-hypo-weakened-next-is-intransaction-trace
description: sess13(ccloop) targeted FUA write-through of released dir blocks (build EE549890, dir_release_fua_write) INERT — still 399/400. LIO-write-cache-vs-pl…
metadata:
  type: project
---

## sess13 (ccloop) — FUA write-through inert; platter hypothesis weakened

### Test (build EE549890, param dir_release_fua_write=1, scoped to released dir blocks)
After the release fence's xfs_bwrite, re-issue each dir block as a SCSI FUA write (mxfs_pal_scsi_write_fua_bdev) to force the platter (LIO drops blkdev flush). RESULT: STILL 399/400, no shutdown. So forcing released dir blocks to the platter does NOT fix the residual → the releasing node's blocks were already reaching the platter (or the loss isn't a peer-read-stale-platter). LIO-write-cache-vs-platter hypothesis WEAKENED.

### P13-COLLIDE garbage = NORMAL transient, not the bug
The off=64 garbage-on-disk is a freshly-allocated dir block whose in-core empty-init isn't yet written back — disk still holds the daddr's prior-life content. Transient, overwritten at flush. Does NOT correlate with the losses. So NOT a placement-onto-occupied-slot and NOT a stale-platter-read of a real entry.

### EXHAUSTED this session (6 builds, 13 cluster runs):
read-coherency (FUA), buffer-lifetime (xfs_buf_stale), fast-path-stale (epoch), master-double-grant (P-DOUBLEGRANT=0), placement-onto-occupied (P13-COLLIDE), write-durability-to-platter (FUA-write). ALL refuted/inert. Winning config 399/400 stable.

### THE definitive next step (sess11run FINAL, never completed): IN-TRANSACTION addname→commit trace
sess11run FINAL [[sess11run-FINAL-entry-vanishes-in-addname-to-commit-window-not-split-not-evict]] is the most precise evidence: the lost dirent is logged (xfs_dir2_data_log_entry, rval=0) then ABSENT from its block at durable_signal — SAME THREAD, ILOCK_EXCL held, ~250us window, the only thing between is xfs_trans_commit + note_dir_modified. So the revert is in the COMMIT path / addname internals, NOT cross-node. Instrument SAFELY (NO fresh xfs_buf_incore in-txn — corrupts; walk tp->t_items or add log lines in xfs_dir2 functions):
1. Log the entry's (daddr, off) at xfs_dir2_data_log_entry (P13-COLLIDE site already there) for the storm dir, ALWAYS-ON.
2. Add a probe in note_dir_modified / the commit hook that, for the storm dir, walks tp->t_items (the buffer log items) and checks whether the dir DATA buffer still carries the just-logged entry's range, BEFORE and AFTER any mxfs commit-path action.
3. Check whether ANY mxfs hook (note_dir_modified bumping i_dlm_dir_gen, or a CIL hook) clears XBF_DONE / triggers a re-read of the dir block within xfs_trans_commit — if so, a same-create later dir access (parent timestamp, leaf update) re-reads from the stale/garbage disk and reverts.
The fact the entry vanishes WITHIN one node's own create transaction means this is likely SINGLE-NODE-REPRODUCIBLE given the right dir-growth + i_dlm_dir_gen state — a much more tractable repro than the 4-node race.

### Builds: ...→ EE54989034228FF68388CCC (all sess13 levers/probes, default-off/storm-scoped, default behavior == 40AC2A0C). dir_reuse 4/tcp = 399/400 best. 8/tcp unrun. Criterion NOT met. See [[sess13run-REFUTED-placement-onto-occupied-slot-P13-COLLIDE-only-fresh-block-garbage]] [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>
