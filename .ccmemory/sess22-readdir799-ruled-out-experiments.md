---
name: sess22-readdir799-ruled-out-experiments
description: sess22(ccloop) dir_reuse readdir799 RULED-OUT experiments (do NOT re-try): dir_evict_prior_tenure=1 (no fix, once shutdown), dir_release_fua_write=1…
metadata:
  type: project
---

## sess22 (ccloop) — readdir=799 RULED-OUT module-param experiments (build EFBB9861)

All tested on 8/tcp dir_reuse (clean reboot each); residual stays `readdir count exp=800 got=799/792` (durable content-divergent clobber). DO NOT re-try these as the fix:

1. **dir_evict_prior_tenure=1** — NO fix (PASS then FAIL readdir=799; once caused a shutdown). The clobber is NOT a stale prior-tenure READ base.
2. **dir_release_fua_write=1** (scoped SCSI FUA write of released dir blocks to force platter past the LIO write-back cache) — NO fix (PASS then FAIL). So LIO-write-back-staleness is NOT the (sole) root; the releasing node's drain IS reaching coherent storage.
3. **Count-based write guards** (release-drain P22 probe, ex_write_guard `disk_cnt>buf_cnt`, dataclobber) — all BLIND: the clobber is count-preserving/content-divergent. ex_write_guard also EX-gated (clobber is under-EX). PROVEN: P22 0× during create, P-DATACLOBBER-SKIP 0×. See [[sess22-readdir799-is-content-divergent-clobber-count-guards-blind]].

### REMAINING ROOT (next session): content-divergent under-EX clobber. A node holding dir EX RMWs a stale base / uses a stale free-slot (bestfree/freeindex from a stale leaf), writing its new entry OVER a peer's live dirent (count ~preserved, peer entry durably lost). This is the sess11/sess13 free-slot DOUBLE-ALLOCATION ("entry vanishes in addname->commit window"). 

### Fix MUST be read-side base coherency (write-side guards can't distinguish legit-remove from clobber by content alone):
On the MODIFY/acquire path, before addname's free-slot search, ensure the in-core data block (AND the free-space metadata it consults: leaf bests / freeindex) is a coherent same-incarnation image of disk. The existing mxfs_dir_refresh_stale_data_blocks (mxfs_dir_coherent_modify, default OFF) + evict (force_evict=1) target the data block but NOT the free-slot/leaf-bests path. KEY hypothesis to test next: the stale FREE-SLOT (bestfree/freeindex), not the data content, drives the double-alloc — instrument the free-slot chosen by xfs_dir2_node_addname / xfs_dir2_data_use_free vs the on-disk occupancy of that offset. Gate any fix on b_mxfs_dir_incarn==i_generation (ghost-reuse guard, sess41 refutation). See [[sess22-readdir799-durable-datablock-clobber-diagnosis]].
