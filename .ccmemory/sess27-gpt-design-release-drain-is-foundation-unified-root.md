---
name: sess27-gpt-design-release-drain-is-foundation-unified-root
description: sess27 GPT(RULE5) design for dir_reuse 2/tcp: root=write-ownership/checkpoint-ordering. Fix=strict DLM release-drain (write+WAIT+invalidate before un…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — GPT-5.5 design consult (RULE 5) for dir_reuse_coherency 2/tcp durable lost-update

### Unified root (mine, GPT-confirmed): INCOMPLETE RELEASE-SIDE DESTAGE
Both observed corruptions are the SAME class = a node writes a STALE cached metadata buffer over the peer's durable newer version, because dirty metadata OUTLIVES its DLM lock tenure (released with buffers still in-AIL/pinned, not destaged to home):
- **Inode-cluster revert** (default partial_iwrite=1): dirent→freed inode. Disabling partial-inode-write (whole writes) FIXES it but EXPOSES →
- **Dir LEAF-hash hole** (whole writes): on re-acquire, node's leaf is in-AIL (own un-checkpointed changes) so the acquire-refresh SKIPS it (P21S-EVICTSKIP-LEAF, in_ail=1 pin=1) → node keeps a leaf with its own entries but MISSING peer's → RMW writes it durably → reverts peer's dirents. Root = the leaf was never fully destaged before the PRIOR release, so it lingers in-AIL.

### GPT verdict (gpt-5.5, full design in transcript)
- **RMW (read-modify-merge-write) is WRONG** as the general model: not atomic vs peer writes (still loses updates without a physical block lock), breaks structured blocks (CRC/LSN/hdr/hash), and "currently-attached log items" (b_li_list) is the WRONG durability predicate.
- **FOUNDATION = strict DLM release/demotion drain**, per resource (per-inode, per-AG, per-dir-inode):
  1. quiesce new txns under the lock; 2. wait active txns; 3. `xfs_log_force_lsn(max_commit_lsn)`; 4. push AIL + submit ALL home-dirty buffers for this lock; 5. **WAIT for write I/O completion**; 6. ASSERT no home-dirty remains; 7. invalidate (xfs_buf_stale) CLEAN cached buffers for this tenure; 8. THEN dlm_unlock. **No buffer with local home-dirty state may survive demotion.**
- **Submit-time guard (backstop, not primary):** at buffer write, if not holding the owning lock epoch: CLEAN stale buffer → skip+stale; DIRTY stale buffer → `xfs_force_shutdown(CORRUPT_INCORE)` (it's an invariant violation = release happened before checkpoint). Extend the existing dir/agmeta/bmbt skip-guards to INODE CLUSTERS (none exists today).
- **partial_inode_write bug**: predicate must be a PERSISTENT per-sector `local_home_dirty` mask (set on modify under EX, cleared only on successful home I/O completion), NOT b_li_list. A freshly-allocated inode whose log item detached before its sector was whole-written stays home-dirty → won't be skipped. Alternative: add a physical INODE-CLUSTER DLM lock (ICLUSTER:<agno>:<cluster_ino>) and whole-write only under it (lock order AG→icluster→inode).
- **Round N-1 free vs round N realloc hazard is REAL** (GPT #4): free writeback (di_mode=0) lands after realloc (di_mode set). Fix = free path must logforce+checkpoint+WAIT+invalidate the inode cluster + inobt + AGI before releasing AG/inode locks, BEFORE peer can realloc. Add inode generation/incarnation guard at write submit to reject stale prior-incarnation writes. GFS2/OCFS2 do exactly this (glock demotion checkpoints journal + invalidates).
- Add explicit lock EPOCH/tenure to every metadata buffer (b_tenure_id exists); born-under-lock tag to avoid false positives on freshly-created blocks (sess17 leaf false-positive).

### NEXT (implementation, RULE 4 — test each in isolation, instr=0)
1. Inspect the dir-inode BAST release drain (mxfs_dir_data_durable / mxfs_dir_push_data_ags / mxfs_dlm_ag_drain_inode_buffers in xfs_mxfs_dlm.c): WHY does the dir LEAF + inode-cluster stay in-AIL/pinned after release? The drain likely pushes but does NOT WAIT for completion, OR misses the leaf (32GB-offset daddr) / inode clusters. Make it write+WAIT+ASSERT-clean before unlock.
2. If release-drain is complete, the acquire-refresh leaf-skip (P21S) disappears (leaf no longer in-AIL) → can refresh → no stale RMW.
3. Add inode-cluster submit guard + (later) the persistent home-dirty mask for partial writes.
Test order: fix release-drain first (addresses BOTH inode + leaf), re-run dir_reuse with DEFAULT args (partial_iwrite=1), verify P26-IGET-FAIL=0 AND lookup_fail=0. Do NOT ship partial_iwrite=0 (false-sharing regression risk for cross_write_read, the test partial-write was added for — sess115).
See [[sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua]] and [[sess27-target-is-LIO-rejects-FUA-reads-handoff-plan-dead]].
</body>
