---
name: sess68-lostupdate-swaps-entries-count-probe-insufficient
description: sess68 FINAL: 4/tcp loss is a stale-base RMW that SWAPS entries (drops specific name while net dirent count grows monotonically) — count probe can't…
metadata:
  type: project
---

## sess68 FINAL CHARACTERIZATION — the 4/tcp lost-update SWAPS entries (count stays monotonic)

Closes the sess68 investigation chain ([[sess68-writeprobe-countdrops-need-incarnation-tag]], [[sess68-MAPDIVERGE-rules-out-extentmap-loss-is-pure-datablock-RMW]]).

### Incarnation-tagged write probe (P68-DWR, build 42A3D0B2) result:
- Within round 19's create wave (node1_f49.md5 lost), NO (daddr,incarn) pair had a dirent-count DECREASE on ANY node — total count grew MONOTONICALLY per incarnation.
- Writes are ~all comm=bash/dd (live foreground create+sync); xfsaild writes are 1-3 total per node (so NOT a stale-writeback/xfsaild-ABA clobber, sess40 family ruled out for this).
- (test1/rank1 had 0 captured P68-DWR — its ring rotated under the rm-rf logging; not meaningful.)

### THE KEY INSIGHT: the lost-update SWAPS entries, it does not shrink the block.
A specific name (node1_f49.md5 / node4_f29.md5 / node3_f1.md5 — varies) is durably dropped while the block's TOTAL dirent count keeps growing. Mechanism: node X acquires EX, reads a STALE block base that is missing peer-entry A but X then adds its own entry B and commits — net count grows (or holds) so a count-based probe sees only monotonic growth, but entry A is durably gone. This is exactly GPT-5.5's bug #1 (same-incarnation stale-base RMW lost-update; di_gen can't catch it, DLM epoch must gate the re-read). It is NOT: extent-map divergence (P68-MAPDIVERGE=0), extent-map durability (gap-B P68-GROWREL-VERIFY DURABLE 48/48), cached-block survival (drop_caches), stale xfsaild writeback (≤3/run), DLM double-grant (sess62).

### WHY THE STALE-BASE RMW HAPPENS despite force_evict + release-drain:
force_evict (pre-RMW, mxfs_dir_evict_data_blocks) drops CLEAN + destaged-in-AIL cached blocks so the RMW cold-re-reads. The release fence (Invariant 1) requires data_durable before unlock. So the cold re-read SHOULD get the peer's committed block. The leak is a tight race on the HOT converged block0 (daddr=120, RMW'd by all 4 nodes every create): either (a) the cold re-read FUA does NOT pierce the SCST/iSCSI target write-cache to the platter (so a peer's just-committed block isn't visible to X's re-read), or (b) X keeps an in-AIL-UNDESTAGED block0 (own un-written work) that is actually a stale fork vs a peer's committed write, or (c) a sub-ms window where X reads block0 between a peer's commit and the peer's release-drain landing it on the platter.

### NEXT STEP (RULE 4, decisive instrumentation):
1. PER-ENTRY (not count) write probe: in xfs_dir3_data_write_verify, for the multinode dir, hash the SET of dirent names and log it, OR track a specific high-risk name's presence. A write of block0 whose name-set is MISSING a name a PRIOR write of the same (daddr,incarn) HAD = the swap-lost-update in the act, with comm + node.
2. Then test the fix: GPT bug-#1 = on EX acquire where DLM epoch advanced, FORCE-invalidate+FUA-re-read the dir DATA blocks before any RMW (epoch-keyed, not gen-keyed). Combined with verifying the FUA re-read pierces the target cache (candidate a). If the re-read is stale-from-target-cache, the fix is in the read path (ensure dir-data cold re-reads use real FUA / SYNCHRONIZE CACHE coherency).
3. Architectural fallback (GPT): epoch-keyed buffer stamp (ino,di_gen,dlm_epoch,dir_cache_seq) validated in xfs_da_read_buf/xfs_dir3_data_read; or inode-lifetime fencing for the reuse.

### SHIP STATE: KEEP gap-B (proven). HEAD build `42A3D0B2D67FFFA84914133` = gap-B + diagnostic probes (P68-DATAINIT, P68-GROWREL-VERIFY, P68-DWR incarnation-tagged always-on) + gated-off (MAPDIVERGE per-block compare, owner-evict). Shipped-proven baseline 91962D4A. CRITERION NOT MET (4/tcp dir_reuse; 1/2 PASS; 8 untested). Cluster healthy test1-4 (test2 was rebooted via virsh after a wedged mxfs-ino-bast D-state kworker blocked rmmod).</body>
