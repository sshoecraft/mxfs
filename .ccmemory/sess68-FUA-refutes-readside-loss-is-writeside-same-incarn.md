---
name: sess68-FUA-refutes-readside-loss-is-writeside-same-incarn
description: sess68: FUA reads enabled (fua_disable=0) STILL fails → read-side staleness REFUTED; loss is a durable WRITE of a block missing the entry (same-incar…
metadata:
  type: project
---

## sess68 — FUA refutes read-side; the 4/tcp loss is a same-incarnation WRITE clobber

Final refutation set for the sess68 dir_reuse investigation.

### NEW decisive refutation: read-side staleness is NOT the cause
Ran `./run.sh 4 tcp dir_reuse_coherency` with `MXFS_EXTRA_MODARGS='fua_disable=0'` (re-enable SCSI-FUA reads so every dir-block cold re-read PIERCES the SCST target cache to the platter). STILL FAILS (lost node3_f27.md5 round 1). So the modifying node reading a STALE block (from the SCST/per-initiator cache) is REFUTED — even reading the true platter image, the entry is lost. The entry is genuinely WRITTEN-missing to the platter. (`mxfs_fua_disable=1` is the default; sess45 set it because FUA caused rename_visibility 372s+shutdown — the coherency model relies on buffer INVALIDATION + SCST's coherent shared cache, not FUA. Enabling FUA doesn't fix dir_reuse and would regress perf — keep default 1.)

### Full refutation tally this session (4/tcp dir_reuse single-entry durable loss):
- extent-map durability at release: gap-B FIXED + confirmed (P68-GROWREL-VERIFY DURABLE 48/48).
- extent-map divergence at modify: REFUTED (P68-MAPDIVERGE=0, full per-block daddr compare).
- cached stale-block survival: REFUTED (drop_caches every round → owner-evict collected=0).
- read-side stale re-read / target-cache pierce: REFUTED (fua_disable=0 still fails).
- gen-detectable staleness, DLM double-grant: REFUTED (prior sessions).

### THEREFORE: the loss is a durable WRITE of a dir DATA block (at a daddr all nodes agree on, P68-MAPDIVERGE=0) that is MISSING a peer-committed entry, SAME incarnation. Net dirent count grows monotonically (the lost-update SWAPS: drops entry A, adds B), so count probes miss it.

### Candidates STILL open (for next session):
1. **xfsaild stale same-incarnation flush**: P68-DWR shows 0-2 comm=xfsaild/sda dir-block writes per node, INCLUDING block0 (daddr=120). The guard `mxfs_buf_xfsaild_skip_dir_write` (xfs_mxfs_dlm.c:17649) only skips (a) DEAD prior-incarnation buffers (b_mxfs_dir_incarn != current i_gen) and (b) NL-released (i_dlm_mode==NL). It does NOT skip a SAME-incarnation stale-content block0 buffer flushed while holding PR/EX. The tenure-mismatch arm is detector-only (false-positive risk per sess17). → Investigate: can a node hold a same-incarnation but STALE block0 buffer (older content than a peer's committed version) that xfsaild then flushes over the fresher platter image? If so, extend the skip to same-incarnation-but-stale-tenure (needs a safe per-block freshness tag that doesn't false-positive on legit conversion writes).
2. **Eviction gap on block0 specifically**: confirm (write-side, not count) that the modifying node actually re-reads the peer's latest block0 before its RMW. The count-based P68-DWR can't show entry-swaps; need per-entry membership (XOR nameset cancels — use a real per-name bitmap or jhash-set logged only when count is suspicious).
3. **GPT-5.5 architectural fix** (if surgical fails): epoch-keyed buffer stamp (ino,di_gen,dlm_epoch,dir_cache_seq) validated in xfs_da_read_buf/xfs_dir3_data_read + at xfsaild write skip; or inode-lifetime fencing (don't reuse inode # cluster-wide while a peer holds the old incarnation).

### INSTR NOTE: dmesg ring rotates within a 24-round run (loses early-round write timeline); the test's /root/drc_create_rN / drc_fail_rN snapshots are per-rank + cumulative. `dmesg -w` streaming to a file does NOT survive run.sh's prep (rmmod + dmesg -C). For clean ground truth, reduce DRC_ROUNDS (env, e.g. DRC_ROUNDS=8 still fails) AND start streaming AFTER prep (or patch run.sh to start it post-insmod).

### SHIP STATE: KEEP gap-B (proven). HEAD build `590E2E89` = gap-B + probes (P68-DATAINIT, P68-GROWREL-VERIFY, P68-DWR with per-entry nameset+incarn) + gated-off MAPDIVERGE/owner-evict. Shipped-proven baseline 91962D4A. CRITERION NOT MET. Cluster healthy test1-4; test2 was rebooted once via virsh (wedged mxfs-ino-bast D-state kworker).</body>
