---
name: sess10run-4tcp-clean-repro-dirty-block-clobber-mechanism
description: sess10(ccloop) clean-cluster 4/tcp dir_reuse repro: 2tcp PASSES, 4tcp FAIL 0/4. Round15 all nodes lost node4_f1.md5 (399/400) durable single-dirent.
metadata:
  type: project
---

## sess10 (ccloop run 4cb2d0a2) — current 4/tcp dir_reuse ground truth (build DE3A7E21)

### Scoping (confirmed this session)
- **1/2 node: baseline INTACT.** `./run.sh 2 tcp dir_reuse_coherency` = PASS 2/2 on DE3A7E21.
- **4 node: FAIL 0/4** on a FRESH virsh-reset clean cluster (not a degraded-node artifact — reproducible).
- **NO FS corruption shutdown.** The earlier "shutdown" greps matched benign `scsipr: unregister on shutdown failed` + module unload; the `xfs_imap_to_bp` stacks are the normal `mxfs_dlm_bast_process` P70 quiesce barrier, not EFSCORRUPTED. No `Internal error`/`EFSBADCRC`/`badcrc`.

### Failure shape
- **Round 15: ALL 4 nodes readdir=399/400, lookup_fail=0, lost = `node4_f1.md5`** (a SIDECAR created by rank4). Clean durable single-dirent lost-update (= sess69 root).
- Later rounds 19/20 degrade further (324/400, test1=0) + P36-RETRY acquire timeouts (×10 on test1) + 1 forced-release — cascade/contention AFTER accumulated damage, not the core bug.

### Mechanism (evidence-backed, refines sess69)
Two nodes concurrently add dirents that land in the SAME leaf/data block. node4 adds node4_f1.md5 to block B, flushes durable (publish-before-notify `mxfs_dlm_dir_durable_signal` xfs_bwrite, EXTENTS/BTREE only, gen>0). A PEER holds block B cached-DIRTY with ITS own adds (missing node4_f1.md5); on the peer's EX reacquire the read-path invalidation (xfs_da_read_buf, gated b_mxfs_dir_gen<i_dlm_dir_gen) **SKIPS the dirty block** (can't clear XBF_DONE on dirty/in-AIL = would lose peer's own work — sess61-DECISIVE "dirty bufgen=0 kept by dirty guard"). Peer RMWs the stale-dirty block, flushes → **clobbers node4_f1.md5**. The peer's block should have been clean (Invariant-1 drain at its prior release) — it wasn't (drain gap / forced-release under load).

### What's ALREADY ON by default and still fails
dir_modify_extent_adopt=1, dir_postread_reread=1, dir_iflush_owner_fence=1, dir_adopt_block=1, dir_force_block=1 (all claim to fix "dir_reuse 4/8-node durable loss"). The modify FAST-PATH handoff check (P63-FASTEX-HANDOFF) FIRES at 4node (4-5/round) but loss persists.

### Gated OFF (candidate fixes, no rebuild needed via MXFS_EXTRA_MODARGS)
`dir_epoch_adopt` (=0; sess64 level-triggered reliable adopt, only on post_release reload path 7420), `dir_leaf_rebuild`(=0, "perturbs"), `dirrefresh`(=0), `dir_merge`(=0, "caused sess65 corruption"), `sf_fastpath_adopt`.

### Key code sites
- Fast-path EX dir serve handoff check: xfs_mxfs_dlm.c ~10583-10613 (one-shot grant_handoff, NOT level epoch).
- Epoch adopt gate (post_release only): ~7420 `if (post_release && dir_grant_epoch > i_dlm_dir_valid_epoch)`.
- consumer_refresh (read path, lookup): ~2728; modify_refresh ~3265.
- Repro: `MXFS_TEST_ENV='DRC_ROUNDS=20' ./run.sh 4 tcp dir_reuse_coherency`; trace add `MXFS_EXTRA_MODARGS='dirwr=2' DRC_STREAM=1`. Lost-entry shows in `mxfs-drc-RDMISS round=N`.

See [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]].</body>
