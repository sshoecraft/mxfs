---
name: sess27-REFUTED-four-mechanisms-residual-is-undetectable-content-lostupdate
description: sess27(ccloop) DECISIVE refutations via dirwr=1 NFS-stream capture (round 7, lost node5_f46.md5): the dir_reuse residual content lost-update is NOT e…
metadata:
  type: project
---

## sess27 — instrumented (dirwr=1 + DRC_STREAM NFS) round-7 capture: four mechanisms REFUTED

Config `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dirwr=1`, DRC_STREAM=1 (per-rank dmesg → /src/mxfs/tests/tcp/drc_cap/stream_rankN.log, ring-rotation-immune). dirwr AMPLIFIES+CHANGES the bug: dirwr=0 → readdir=728 whole-block (~72 node3 entries); dirwr=1 → readdir=799 single-entry (node5_f46.md5). Same root, timing-dependent magnitude.

### The lost entry (node5_f46.md5, round 7, ALL 8 nodes agree readdir=799)
- Durable: LOOKUP_ENOENT + REREAD_MISS. At verify, DSCAN-MISS scanned=801 (800-1 +./..) — genuinely ABSENT from all 6 data blocks on disk. P33-DSCAN-ONDISK: incore_size==disk_size==24576, sameincarn=1 (NO extent-map / incarnation divergence).

### DECISIVE refutations (probe counts in the round-7 create window t=102..111, ino=131):
1. **Extent-map divergence — REFUTED**: P68-MAPDIVERGE=0 on ALL ranks (extent_adopt's per-block daddr compare never found divergence at modify-prelock).
2. **Release-durability — REFUTED**: P68-GROWREL-VERIFY = STALE-DISK 0 / DURABLE 33-59 per rank; P68-DIRINODE-DURABLE-FAIL=0. The grown dir inode (di_size+nx) IS durable before unlock (mxfs_dlm_dir_inode_durable, called at xfs_mxfs_dlm.c:7424 BEFORE DLM unlock).
3. **Read-side detectable staleness — REFUTED**: P60-GENMATCH-STALE=0, DIR-STALE-SKIP=0 on ALL ranks; ALL ~1600 P-TDS-RMW have stale_base=0 (dir_gen==loaded_gen) + held=1. Every clobbering RMW base is considered FRESH (gen-current, EX-held).
4. **Concurrent-EX / double-grant — REFUTED**: P-DOUBLEGRANT=0, P-STALEMASTER=0, P106-STALE-EX=0. Fine-grained P-TDS-RMW realns (per-rank, mode=5) SERIALIZE: e.g. r2 holds 808.60-808.77ms then r5 808.78-808.91ms, sequential not interleaved. The coarse per-rank min/max range overlap is scattered interleaving (each rank's tenures span the whole phase with gaps), NOT continuous concurrent hold.

### NARROWED root (the only surviving shape)
A dirent content lost-update on a block ALL detectors consider fresh (gen-current b_gen==dir_gen, EX-held, durable, no extent/incarnation divergence). Mechanism must be: a stale cached data block served as the RMW base WITHOUT b_gen<dir_gen tripping (so DIR-STALE-SKIP can't fire) AND the block is dirty/in-AIL so P60-GENMATCH-STALE (clean-only, else-if at xfs_da_btree.c:3473) is skipped. I.e. a node's own in-AIL cached block B (b_gen==dir_gen) whose content a peer superseded, served at re-acquire because the handoff that should have bumped dir_gen either didn't, OR the slow-path reload (P63-HANDOFF "forces disk-superset adopt") adopts the inode extent map but does NOT re-read the in-AIL DATA block content (keep-guard). NOTE: FASTEX-EPOCH=0 always (fast-path epoch never fires — correct, fast path is within a continuous hold so no peer modified). ~85 P51-REL vs ~29 P63-HANDOFF in the window (8 nodes, 8s).

### NEXT (sess28): (a) re-read the eager-invalidation-at-release keep-guard (xfs_mxfs_dlm.c ~2430+) and the slow-path reload's DATA-block handling — does P63-HANDOFF reload re-read in-AIL data blocks or only adopt the inode? The in-AIL keep-guard skipping a peer-superseded data block at reload is the prime suspect. (b) handoff-frequency experiment: raise inode_mht_ms (300→1000) to batch more creates/tenure → fewer tenure-boundary windows; if loss vanishes, root is tenure-boundary handoff. Harness: tests/tcp/drc_catch3.sh (dirwr+stream), tests/tcp/drc_catch2.sh (clean capture). Streams: tests/tcp/drc_cap/. See [[sess27-CONFIRMED-residual-is-dir-extent-map-revert-not-dirent-content-loss]].
