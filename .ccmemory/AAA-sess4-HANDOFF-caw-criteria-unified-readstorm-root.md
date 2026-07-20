---
name: AAA-sess4-HANDOFF-caw-criteria-unified-readstorm-root
description: ENTRY POINT after sess4 (12e0d157): 1/2/4/8=17/17, 16=16/17(dir_reuse), 32=13PASS/1FAIL/3PEND. ALL 5 remaining cells reduce to ONE fix: 32-node cold…
metadata:
  type: project
---

## NEXT-SESSION ENTRY POINT — caw criteria "1/2/4/8/16/32 node 100%" (ccloop 12e0d157 sess4)

### CRITERIA STATE (criteria.json). Marker NOT written. ONLY 5 test-cells remain, ALL one root.
- 1/2/4/8 caw = **17/17** each. 16/caw = **16/17** (only dir_reuse_coherency PENDING).
- 32/caw = **13 PASS / 1 FAIL / 3 PENDING** (sess4 advanced it 6->13: added dlm_membership,
  fence_during_write, fault_netpartition, soak, dlm_lock_correctness, scaling_curve, rsync_paired).
  FAIL: dlm_scaling(6/32). PENDING/failing: cache_coherency(timeout 0/32 even CLEAN substrate),
  crash_consistency, dir_reuse.
- **THE 5 REMAINING CELLS = dir_reuse@16, dlm_scaling@32, cache_coherency@32, crash_consistency@32,
  dir_reuse@32 — ALL blocked on the SAME root** (below). Fix it once -> criteria met.

### THE ONE ROOT: 32-node COLD INODE-CLUSTER READ-STORM saturates the shared iSCSI target
At high node count, shared metadata (root ino128 + .dlm_scaling + reused-dir inodes, AG0 fsblk
~18300-18700) is EVICTED then re-read COLD (plain cache-miss bio, ~31000-41000 reads/3-4s), agg
~1319 cmd/s -> <50/s/node. dlm_scaling FAILs the 50/s floor; cache_coherency/crash_consistency/
dir_reuse-verify do drop_caches + full cold re-read -> exceed their run.sh budgets (RULE-0 timeout
FAIL). "global eviction off (dir_release_invalidate=0 dir_force_evict=0) -> 29/32" PROVES eviction
-driven cold re-reads dominate. Coherency FAMILY that does NOT drop_caches (strong_consistency,
posix_multi, mmap, zero_silent_loss) PASSES 32/32 — so it's the cold-read path, not a coherency bug.

### sess4 CORRECTION (RULE-4): storm is INODE-cluster reads, NOT dir-DATA-block reads.
P-DSCAN probe (in xfs_da_read_buf) fired only 6x during a live dlm_scaling@32 run -> the storm does
NOT flow through the dir-block read path. So `dir_shared_pr_skip` (my param, default 0, inert)
CANNOT help — repurpose/remove. Storm is at `xfs_imap_to_bp` (xfs/libxfs/xfs_inode_buf.c:318 ->
xfs_trans_read_buf at imap->im_blkno). RULED OUT as evictor: `mxfs_dlm_ag_drain_inode_buffers`
(xfs_mxfs_dlm.c:23368) only FLUSHES dirty inode bufs, doesn't evict clean ones. See
[[caw-sess4-inode-readstorm-code-map-drain-only-flushes-dirty]].

### NEXT-SESSION FIX PLAN (unblocks all 5 cells)
1. **Eviction-provenance probe** (fresh cluster): tag every xfs_buf_stale/eviction of an INODE buffer
   with reason {BAST_EX,BAST_PR,MHT,NOINO,LRU,SELF}; identify WHAT evicts the clean shared inode
   buffers. (Fable ranks MHT idle-demote / noino BAST collateral / DLM LRU.) A miss-counter at
   xfs_imap_to_bp is risky (xfs_buf_incore holds/locks in a hot path) — prefer ftrace (tests/trace_
   reads.sh) + the stale-site tags.
2. **Scoped eviction-prevention (GFS2 glock principle):** retain cached inode/dir buffers while the
   inode is held >=PR; invalidate ONLY on a real EX BAST (NOT MHT/idle/noino/LRU). Full Fable design:
   [[caw-32node-dlm_scaling-FIX-progress-and-fable-design]] steps 2-5.
3. Validate each change vs dlm_scaling@32 + cache_coherency/crash_consistency/dir_reuse @16/32.

### BUILD 6C6D5274 (deployed). New params DEFAULT-SAFE.
- `dir_persig_flush` (1=default, 0=never, 2=only-when-peer-wants-EX): **=2 FIXES the dir_reuse rm-rf
  HANG** (per-unlink log_force(SYNC)+dir-flush in mxfs_dlm_dir_durable_signal) AND stays COHERENT
  (EX-release drain mxfs_dir_data_durable enforces durability, sess98). But dir_reuse RESIDUAL: reuse
  rounds create-storm (reused-inode reload = the SAME read-storm). Make persig_flush=2 default after
  validating 1/2/4/8 dir_reuse don't regress. [[caw-sess4-dirreuse16-reuse-round-reload-storm-is-perf-blocker]]
- `dblalloc_probe`(0): P-DBLALLOC detector off (it did 1 sync LUN read/data-alloc = confound). Removed
  un-gated P-AGLOW. `dir_shared_pr_skip`(0): misdirected (see above), inert. P-DSCAN probe (dirwr-gated).

### INFRA (sess4)
- Substrate DEGRADES ~2-3 runs/boot (unmounts, PR errors). FRESH-boot all N (parallel virsh
  destroy+start) + `scripts/caw_preflight.sh N` (~20-80s) before trusting results. Multipath=2 healthy
  paths (not the bottleneck). Do NOT kill run.sh mid-workload (busy mounts -> next prep power-cycles
  ~180s/node); use virsh destroy (force). SSH: `tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass 'CMD'`.
  run.sh forwards MXFS_TEST_ENV= (DRC_ROUNDS=) + MXFS_EXTRA_MODARGS= (insmod). Bash TOOL default
  timeout 120s — set `timeout` (prep ~130s; cache_coherency@32 >300s budget). `make modules` ~16-24s.
See [[caw-sess4-dirreuse16-root-and-clean-build-params]] [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]].
</body>
