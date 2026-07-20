---
name: sess13run-HANDOFF-FINAL-state-residual-likely-in-transaction-revert-next-instrument-addname
description: sess13(ccloop) FINAL HANDOFF: dir_reuse 4/tcp = 399/400 (winning config), corruption eliminated. force_evict ESSENTIAL (off=374/400). Residual robust…
metadata:
  type: project
---

## sess13 (ccloop 4cb2d0a2) — FINAL session handoff

### ACHIEVED (verified, build 21A59021)
- WINNING CONFIG `fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1` → dir_reuse 4/tcp **399/400, ZERO corruption/shutdowns** (was 0/400 + ~150 DABUF_MAP_HOLE shutdowns/node). Corruption ELIMINATED.
- dir_force_evict is ESSENTIAL: force_evict=0 → 374/400 (26 lost). It prevents ~25 of 26 losses; NOT the residual cause.
- Residual = exactly 1 durable .md5 dirent lost/run, ROBUST across every lever (fua, epoch, mht 0/300/2000, cohmod, release-invalidate, fast-path-epoch).

### CODE ADDED this session (build 21A59021, ALL gated OFF by default → default behavior == 40AC2A0C, no regression, no shutdown):
- param `dir_release_invalidate` (default 0) + helper mxfs_dir_release_invalidate_data_blocks (post-fence clean-block invalidate) — inert.
- xfs_buf_stale publish-and-discard after dir-block xfs_bwrite in mxfs_dir_flush_data_blocks (gated dir_release_invalidate) — inert.
- fast-path level-triggered epoch check in mxfs_dlm_ilock_begin (~line 11100, gated dir_epoch_adopt) — fired 1x, inert.

### TOP NEXT LEAD (RULE 4) — the residual is an IN-TRANSACTION revert, NOT cross-node
sess11run FINAL [[sess11run-FINAL-entry-vanishes-in-addname-to-commit-window-not-split-not-evict]] PROVED (PRELOGF, single thread comm=bash, ILOCK_EXCL held continuously, NO split, NO evict, NO peer-BAST): the lost dirent is logged (P11-DATALOG, rval=0 commit OK) then VANISHES from its in-core CACHED data block within ~250us between addname and durable_signal — INTERNAL to the create transaction. Candidates: (a) xfs_dir2_node_addname xfs_trans_roll commits an intermediate tp then re-reads the data block from a source missing the entry; (b) a dir2 leaf/node addname freespace path that adds (count++) but the bytes land in a region REUSED later in the SAME transaction; (c) an mxfs commit/CIL hook reverting the buffer.
ALREADY RULED OUT as the revert source: the read-time XBF_DONE-invalidation hook (xfs_da_btree.c ~3173) is solidly guarded (skips dirty/in-AIL/pinned/delwri — sess43/sess64); mxfs_buf_read_fua P91 guard skips pinned/log-item buffers. So neither the read hook nor FUA reverts an in-flight block.
NEXT INSTRUMENT (sess11run's unfinished step; SAFE method — do NOT use fresh xfs_buf_incore inside the txn, it corrupts; walk tp->t_items or add log lines IN xfs_dir2_data_log_entry / xfs_dir2_data_make_free / xfs_dir2_node_addname): in xfs/libxfs/xfs_dir2_node.c xfs_dir2_node_addname + xfs_dir2_leaf.c, log the data block (db/daddr/off) the entry is written to AND whether xfs_trans_roll runs between the data-write and return, for the storm dir (ino<=256). Correlate with PRELOGF. This localizes the exact revert step → then the surgical fix.

### Other criterion gaps: 8/tcp NEVER run (must do after 4/tcp). Re-verify fence_during_write/fault_netpartition/tcp_dlm_scaling/soak standalone (last full-run fails were likely cascade after dir_reuse/fence shutdown).
### RULE-0: fua_always too slow — scope FUA to dir-meta-on-handoff once correct. prep_node.sh passes NO params, so the winning config must become source DEFAULTS (or a scoped mechanism) for the criterion harness.
Cluster test1-8 (virsh -c qemu:///system). Criterion NOT met. See [[sess13run-FASTEPOCH-inert-four-fixes-exhausted-residual-not-staleread-not-doublegrant]] [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>
