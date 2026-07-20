---
name: sess34-HEAD-removed-set-drain-merge
description: sess34 HEAD: epoch-skip REFUTED (loss-block current-tenure). Removed-set drain-merge built; per-block dedup caused 801 cross-block-dup. Added global…
metadata:
  type: project
---

## sess34 HEAD — read first. CRITERIA NOT MET (1/2/4 tcp=100%; 8/tcp blocked by dir_reuse readdir loss).

### BUILDS: keeper=275EF4D4. sess34 work: 8F1E17A0 (removed-set merge, per-block dedup) → REFUTED. **DBD82AB2** = + whole-dir GLOBAL dedup (mxfs_dir_name_incore_global). ALL new params default 0 (dir_drain_merge, dir_drain_epoch_skip). Reboot→keeper. SAFE.

### ★ PROVEN (RULE 4, P34-DRAINEPOCH probe at the release-drain loss site):
The loss-block is **CURRENT-tenure** — `b_epoch==valid_epoch==master_epoch, disk_extra=1, undestaged, in_ail, comm=rm`, UNIFORMLY (test1 ~795/epoch = LEGIT rm-rf removes: disk_extra=1 is the just-removed dirent still on disk). **REFUTES epoch-skip (dir_drain_epoch_skip)** and proves flags can't discriminate legit-remove from the rare loss — the discriminator is PROVENANCE (which inumber).

### REMOVED-SET drain-merge (the disambiguation):
- `i_dlm_dir_removed[]` per-inode (n/cap/epoch + INVALID sentinel 0xFFFFFFFF), populated in `xfs_dir_removename`→`mxfs_dir_record_removed` (ILOCK_EXCL), reset on valid_epoch change, freed in xfs_inode_free_callback.
- `mxfs_dir3_data_drain_merge(dp,bp)` (pal/linux/xfs_buf.c) at `mxfs_dir_flush_one_daddr` BEFORE the release bwrite: graft a disk-only-by-name dirent ONLY if inumber ∉ removed-set (peer add, not our remove). Fired SURGICALLY (1-2×, not 100s) — removed-set correctly avoids over-grafting our removes.

### ★ 8F1E17A0 REFUTED (per-block dedup): round3 readdir=**801** + lookup_fail=1 missing=node7_f17.md5, round4=751. The merge's name-dedup was PER-BLOCK only → a peer entry living in in-core block A is grafted AGAIN when draining disk block B = CROSS-BLOCK DUPLICATE (801) + leaf desync (lookup_fail). This is the SAME wall sess29 hit at the bio chokepoint ("can't verify global name-uniqueness from one block").

### DBD82AB2 fix (the drain site's advantage over the chokepoint = it has `dp`): added `mxfs_dir_name_incore_global(dp,name,len,skip_daddr)` (xfs_mxfs_dlm.c) — walks ALL in-core dir DATA blocks (TRYLOCK, skip current) and grafts ONLY a name absent from the WHOLE in-core dir. Should kill the 801. **TESTING NOW: `drc_repro_loop.sh 6 "dir_drain_merge=1" 24` (no dirwr — P34-DRAINMERGE still logs).**

### OPEN RISK (leaf-desync): a GENUINELY-lost peer entry that IS grafted lands in the DATA block but NOT the leaf hash → lookup relies on sess22 datascan-heal (node-format leaf-hash-hole READ heal). If iter shows readdir=800 but lookup_fail>0, graft-without-leaf-insert is the wall → either insert into leaf (complex, sess21 offset-collision risk) or arm MXFS_IF_DIR_LEAF_STALE rebuild (noted harmful: bnobt double-free) or ABANDON graft and pivot to acquire-side new-tenure refresh (dir_newtenure_evict + BLI-retire; sess41 says acquire-refresh is racy but at FIRST modify of a NEW tenure disk is authoritative so a content-divergence refresh is safe there).

### NOTE: DABUF_MAP_HOLE storm under dirwr=1 is BASELINE (test1: 0 merges yet 1558 holes) — a probe-perturbation artifact, NOT merge-induced. Run WITHOUT dirwr for representative results.
[[sess33-HEAD-handoff]] [[sess33-union-merge-ambiguous-acquire-refresh-is-root]]
</body>
