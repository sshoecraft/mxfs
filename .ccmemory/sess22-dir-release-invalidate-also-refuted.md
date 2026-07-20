---
name: sess22-dir-release-invalidate-also-refuted
description: sess22(ccloop) dir_release_invalidate=1 (release-side dir-block invalidation) REFUTED for readdir799: still fails (783/793) + 2-node shutdown. So rel…
metadata:
  type: project
---

## sess22 (ccloop) — dir_release_invalidate also refuted; acquire-side evict is the path

### dir_release_invalidate=1 (8/tcp dir_reuse, keeper D589FA5F): FAIL readdir 783/793 + 2-node SHUTDOWN. Release-side invalidation of cached dir blocks does NOT fix the readdir=799 durable clobber and adds instability.

### COMPLETE list of REFUTED approaches for readdir=799 this session (do NOT re-try as-is):
- dir_evict_prior_tenure=1 — no fix
- dir_release_fua_write=1 — no fix (not LIO writeback staleness)
- dir_leaf_rebuild=1 — harmful (bnobt double-free shutdown)
- Layer-3 addname free-slot guard (xfs_dir2_node.c, KEEP-harmless) — fired 0× → NOT an addname double-alloc
- dir_stale_incarn_skip=1 (EX-held write suppression) — CATASTROPHIC (474/800, 4-node shutdown)
- dir_release_invalidate=1 — no fix + 2-node shutdown
- ALL count-based write guards (P22 release probe, ex_write_guard/P-DATACLOBBER-SKIP) — 0× / count-blind

### THE FIX (next session, careful code change — NOT a param): ACQUIRE/MODIFY-side force-evict.
Root (sess69 + this session): the EX holder RMWs a STALE base — a prior-tenure dir DATA block that is a cross-node stale READ-CACHE HIT (fua=0) or kept in-AIL-undestaged, never re-fetched. Fix = on EX (re)acquire / modify-evict, for any CLEAN+DONE dir-fork block (data+leaf+freeindex) whose `b_mxfs_dir_gen < ip->i_dlm_dir_gen` (prior tenure), clear XBF_DONE (force a disk re-read) BEFORE the RMW — regardless of count/content (re-reading from disk is always correct; our own work was drained at our prior release per Inv 1). Sites: mxfs_dir_evict_data_blocks (modify path, xfs_mxfs_dlm.c ~2683+) and/or mxfs_dir_drain_evict_data_blocks (acquire path, ~5206+). The sess41 evict-refresh block (~2883, param mxfs_dirrefresh default 0) is the RIGHT site but is COUNT-gated ("disk strictly MORE", fires 0× on count-preserving loss) — re-gate it to fire on `dc_stale` (bgen<dir_gen) alone. HARD GUARD: only clear XBF_DONE on a clean (!dirty !pinned !delwri) DONE block — clearing it on a dirty buffer = CORRUPT_INCORE shutdown. Implement as a default-OFF param first (dir_stale_evict), test =1 on 8/tcp dir_reuse, make default once proven. See [[sess22-REFUTED-exheld-stale-write-suppression-harmful]] [[sess22-freeslot-guard-0x-loss-is-postadd-stale-destage]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]].

### Keeper D589FA5F unchanged (functionally == 8948C889). Cluster rebooted clean.
