---
name: sess28-remaining-dir-disize-revert-after-genfix
description: sess28 post-gen-fix: dir_reuse 2/tcp remaining failure = dir DATA-block content lost-update (readdir ~184-188/200, ~12-16 dirents lost, lookup_fail=0…
metadata:
  type: project
---

## sess28 — dir_reuse 2/tcp remaining failure AFTER the inode-revert gen fix ([[sess28-ROOTFIX-inode-revert-fresh-gen-on-create-reuse]])

### Current signature (builds C887AFA3 → 0270D870, gen fix active)
- `drc round=11-12 readdir=184-188/200 lookup_fail=0 missing=[]` — ~12-16 dirents DURABLY MISSING from the shared dir's data blocks; every LISTED entry is lookup-able.
- Failing round drifts 15→12→11 across runs (timing/race-dependent, not structural).

### RULED OUT (decisive, RULE 4)
- **Inode-revert**: P26-IGET-FAIL=0, P25-RESURRECT-SKIP=0, lookup_fail=0 (gen fix C887AFA3 fixed it).
- **di_size WRITE-revert**: enabled P133-DIRINO-REVERT under the lightweight `iwr` flag (pal/linux/xfs_buf.c ~3135, gate now `instr||dirwr||iwr`; P36-DINO-WR re-gated to instr||dirwr to avoid an ino-131 flood). **P133-DIRINO-REVERT count = 0 on BOTH nodes** → NO node writes a smaller di_size/nextents over a larger COHERENT on-disk image. So the di_size oscillation (P26-DSCAN ndb=1 size=4096 seen earlier) is NOT a write-side shrink; it is node-to-node DIVERGENCE (a grower's in-core 8192 not propagated/durable to the peer), or a pure DATA-block content loss with di_size intact.

### REMAINING ROOT (narrowed): dir DATA-block (xfs_dir3_data_buf_ops) content lost-update
Two nodes concurrently add 100 dirents each into the shared dir. ~12-16 of one node's dirents are durably lost from a data block. Classic "Face B" dir-block lost-update (see old [[sess83_lessons]], [[sess88_lessons]]): a node RMWs a dir data block on a STALE cached base (missing the peer's recent dirents) and writes it back, reverting them; OR the peer's adds were never durable.

### STRONG SUSPECT for next session: i_dlm_dir_gen==0 bypass on the per-round-recreated dir
The dir-block READ-time invalidation (xfs/libxfs/xfs_da_btree.c ~3047-3081, b_mxfs_dir_gen < dp->i_dlm_dir_gen → invalidate+re-read fresh) is GATED OFF when `dp->i_dlm_dir_gen == 0` (single-node optimization; xfs/xfs_mxfs_dlm.c:9972 also early-returns on gen==0). The test rm-rf's + mkdir's the dir EVERY round → the dir inode is a fresh incarnation with `i_dlm_dir_gen` RESET to 0 (mxfs_dlm_inode_init xfs_mxfs_dlm.c:9681). There is a bump-0→1 in xfs_da_btree.c:3064-3081 on a multi-node dir-block read, but there is likely a WINDOW where gen==0 and a stale cached block is RMW'd before the bump/invalidation. i_dlm_dir_gen++ sites: xfs_mxfs_dlm.c:8604, 11408 (verify these fire on dir EX ACQUIRE for the reused dir).

### NEXT (RULE 4)
1. Instrument: detect a dir DATA-block write whose live-dirent count < the COHERENT on-disk block's count (the P56 leaf-clobber analogue, but for xfs_dir3_data_buf_ops) under `iwr` — confirm write-side revert vs durability.
2. If read-stale RMW: ensure i_dlm_dir_gen is bumped (and dir blocks invalidated) on EVERY dir EX acquire even for a freshly-created/reused dir (gen==0 must still invalidate in multi-node), so the RMW base is fresh.
3. Then full `./run.sh 2 tcp` ×3 = 100%.
KEEP: gen fix (xfs_icreate fresh i_generation), sess28 inode-write skip, iwr probes. Build 0270D870. Reboot cluster before runs (test2 rmmod-wedge).
</body>
