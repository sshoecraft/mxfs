---
name: sess68-FINAL-epoch-not-enough-datablock-durability-next
description: sess68 FINAL: epoch_adopt+gap-B clean run STILL count-loses (node2_f37.md5); residual is data-block RMW lost-update independent of extent map. Next:…
metadata:
  type: project
---

## sess68 FINAL — epoch_adopt is NOT the count-loss fix; residual is a dir-DATA-block lost-update

Builds on [[sess68-gapB-CONFIRMED-residual-is-datablock-RMW-lostupdate]].

### Decisive clean run (build D3EA5B8D, gap-B confirmed + epoch_adopt=1, 4/tcp):
- FAIL: single durable count loss `node2_f37.md5` LOOKUP_ENOENT on ALL 4 nodes, 1 round.
- P68-GROWREL-VERIFY: durable=17 STALE=0 → extent map IS durable at release.
- So epoch_adopt + gap-B STILL loses a data-block entry. The earlier "epoch_adopt → RDMISS=0" observation was a LUCKY run (failure is ~1/15 rounds; that run failed on leaf-hash instead). **epoch_adopt does NOT reliably fix the count loss.**

### CONCLUSION (high confidence): the 4/tcp dir_reuse residual is a dir-DATA-BLOCK content lost-update that is INDEPENDENT of:
- the inode extent map (durable at release via gap-B — KEEP that fix),
- the extent-map reload on acquire (epoch_adopt),
- cached-block survival (drop_caches drops them; owner-evict collected=0).
A node writes a dir DATA block missing a peer's just-added dirent, and it lands last on the platter. Lost entries are typically late .md5 sidecars (node2_f33.md5, node2_f37.md5, node4_f40.md5) or early data files (node3_f2, node1_f15) — i.e. any block under concurrent 4-way RMW.

### NEXT INVESTIGATION (RULE 4, the unprobed link):
There is NO probe on dir-DATA-BLOCK durability at release (only the INODE via P68-GROWREL-VERIFY). Add one:
1. In the EX-release drain (`mxfs_dir_data_durable` / the release path in xfs_mxfs_dlm.c ~5711), after the data-block flush, for each dir DATA block FUA-read the daddr and compare dirent-content/count to the in-core buffer. If disk has FEWER entries than in-core → the data block was NOT made durable before handoff (data-block release-durability gap = the lost-update root). This is the data-block twin of the P68-GROWREL-VERIFY inode probe that just CONFIRMED the inode path.
2. AND/OR a cold-read coherency check: after a peer's release, does THIS node's FUA re-read of block0 return the peer's just-committed dirents, or stale (SCST/LIO write-cache not pierced by the FUA read)? CLAUDE.md notes "LIO target drops SCSI FUA bit" — but cluster is SCST (project_test_cluster_scst). Verify the dir DATA-block cold re-read actually pierces the target cache to the platter.
3. If durable-but-still-lost: the loss is a concurrency window in the RMW serialization itself (two nodes' block0 writes interleave). Then GPT-5.5's epoch-keyed buffer-stamp `(ino,di_gen,dlm_epoch,dir_cache_seq)` validated in xfs_da_read_buf/xfs_dir3_data_read, or the inode-lifetime fencing, is the architectural fix.

### KEEP for shipping: gap-B fix only (mxfs_dlm_dir_inode_durable non-LOCAL, dirty-gated — proven correct, no 1/2 regression expected; RE-VERIFY 1/2 tcp). The owner-evict (moot, collected=0) and epoch_adopt (insufficient) are NOT the fix. Probes P68-DATAINIT, P68-GROWREL-VERIFY are cheap KEEPs.

CRITERION NOT MET. Build D3EA5B8D, cluster healthy (test1-4 mounted), test5-8 up for 8/tcp.</body>
