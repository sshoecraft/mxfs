---
name: sess13run-CORRECTION-dir-is-LEAF-format-probe-belongs-in-data_log_entry-loss-varies
description: sess13(ccloop) CORRECTION: P13-NADD in xfs_dir2_node_addname_int fired 0x — the 400-entry storm dir is LEAF format (not node), addname goes via xfs_d…
metadata:
  type: project
---

## sess13 (ccloop) — probe-path correction + loss-variance finding (build AE7F9B89)

### CORRECTION: the storm dir is LEAF format, not NODE
Added an always-on placement probe P13-NADD in xfs_dir2_node_addname_int (xfs/libxfs/xfs_dir2_node.c) → fired **0 times**. So the 400-entry dir_reuse storm dir is **LEAF format** (xfs_dir2_leaf: multiple 4KB data blocks + 1 leaf block; dir_force_block=1 forces ≥block, 400 entries overflow one block → leaf). addname therefore routes xfs_dir2_leaf_addname (xfs/libxfs/xfs_dir2_leaf.c) → xfs_dir2_data_use_free + xfs_dir2_data_log_entry — NOT xfs_dir2_node_addname_int. Any per-format probe must go in xfs_dir2_leaf_addname or the COMMON xfs_dir2_data_log_entry (xfs_dir2_data.c:1212, where P11-DATALOG already is).

### Loss VARIES per round (NOT always exactly 1)
Same winning config, this run: round 1 = 399/400 (1 lost), round 4 = 374/400 (26 lost). So the residual is contention-dependent (1-26 lost/round), not a fixed single-entry race. Earlier "exactly 1" was just the last failround sampled. This means it's a RATE (more concurrent .md5 collisions in heavier rounds), consistent with a free-slot double-allocation whose frequency scales with overlap.

### THE decisive probe to build next (minimal perturbation — fires ONLY on the collision):
In xfs_dir2_data_log_entry (or right before it in xfs_dir2_leaf_addname), for the storm dir (ino<=256), do a COHERENT plain-bdev read of the data block being written (mxfs_pal_bdev_read_plain_bdev into a kmalloc temp — does NOT touch the buffer cache, so SAFE in-transaction; this is what mxfs_dir_refresh_stale_data_blocks already does) and check whether the byte offset we are about to place at already holds a DIFFERENT, non-free dirent ON DISK. If yes → log P13-COLLIDE ino/daddr/off/our_name/disk_name/comm. This DIRECTLY catches the double-placement at the moment it happens and identifies whether the disk already had a peer's entry there (→ our base was stale despite all coherency) vs the slot was free on disk (→ pure concurrency / the peer's write not yet durable). Then the fix follows from which case fires.
CAUTION (sess11run): do NOT use a fresh xfs_buf_incore in-transaction (corrupts — drops the txn buffer lock). plain-bdev read into a temp is the safe idiom.

### Builds this session: 40AC2A0C → 3091C841 → D7F1FC0B → 21A59021 → AE7F9B89 (all gated levers default-off + the inert P13-NADD probe; default behavior unchanged). dir_reuse 4/tcp best = 399/400 (winning config). Criterion NOT met. See [[sess13run-HANDOFF-FINAL-state-residual-likely-in-transaction-revert-next-instrument-addname]] [[sess11run-DIRECTIONALITY-later-writer-stale-bestfree-loses-fix-coherent-refresh]].</body>
</invoke>
