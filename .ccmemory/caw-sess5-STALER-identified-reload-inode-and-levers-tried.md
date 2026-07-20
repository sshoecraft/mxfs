---
name: caw-sess5-STALER-identified-reload-inode-and-levers-tried
description: sess5 REFINED: the 32-node inode-cluster staler = mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:14417) on reused-inode grant + bast_process. MHT-up HURTS. Fi…
metadata:
  type: project
---

## sess5 REFINED — the inode-cluster STALER identified + levers tried (ccloop 12e0d157)

### THE STALER (RULE-4 proven via xfs_buf_stale attribution probe, build D1E1911C, param read_attr_probe=1)
dump_stack at xfs_buf_stale on INODE buffers during dlm_scaling@32 shows TWO callers:
1. **`mxfs_dlm_reload_inode` → xfs_buf_stale (xfs/xfs_mxfs_dlm.c:14417)** — the dominant one. reload_inode
   invalidates the cached inode-cluster buffer ("the other node wrote updated data... force re-read")
   whenever it runs. Then the FUA gate cold-FUA-re-reads it = the storm.
2. **`mxfs_dlm_bast_work_fn → mxfs_dlm_bast_process → xfs_buf_stale`** — BAST-driven inode stale.

### WHY reload_inode fires in dlm_scaling (private subdirs, no real coherency need)
- dlm_scaling does `:>f$i; stat; rm f$i` × 2000 → each rm FREES the inode (releases its DLM lock),
  each create REUSES a freed inode#. Re-acquiring the reused inode's grant → the grant callback runs
  reload_inode (gate `VFS_I(ip)->i_mode==0 || i_dlm_stale`, e.g. xfs_mxfs_dlm.c:405; main ilock path
  ~18123). mode==0 (freed shell) or i_dlm_stale (set on grant, src=8 @18111) → reload → stale cluster
  → FUA re-read. Consecutive reused inodes share ONE cluster → each op re-stales+re-reads it = storm.
- reload_inode's stale is CORRECT when a PEER freed+realloced (dir_reuse cross-node). It is PURE WASTE
  when THIS node freed+realloced its OWN private-subdir inode (no peer ever touched it) — the dlm_scaling
  and single-node-write coherency case.

### THE FIX DIRECTION (Fable's prior-owner design; coherency-critical, NOT yet implemented)
Skip reload_inode's cluster-stale (and the FUA re-read) when the grant shows **THIS node was the prior
EX owner** / no peer held the lock since our release → nothing to adopt, in-core is authoritative.
The grant already carries a cross-node handoff signal (genuine_handoff / grant_gen / dir_epoch / prior
EX owner slot — see reload_inode header @13894-13903). Gate the stale on `prior_ex_owner != self`.
RISK: sess79 "skip FUA when AG owned" WEDGED (ILOCK hung-task serving a pre-acquire stale buffer); the
safe scoping keys on prior-OWNER (per-inode grant lineage), not AG-ownership. Implement PARAM-GATED
default-off, validate on cache_coherency+strong_consistency+dir_reuse @4 AND @16 (coherency MUST hold)
before trusting, then dlm_scaling@32.

### LEVERS TRIED THIS SESSION (empirical, fresh substrate each)
- **inode_mht_ms=5000 dir_sf_mht_ms=2000 → CATASTROPHICALLY SLOW** (dlm_scaling@32 ran >11min in
  op-loop, no result — holding inodes 5s serializes the reused-create loop). DO NOT raise MHT high.
  (Default inode_mht_ms=300 dir_sf_mht_ms=40.) sess4's dir_sf_mht_ms=10000→9/32 was marginal/degraded.
- **HIGH VARIANCE**: fresh dlm_scaling@32 = 5/32 to 28/32 across runs (the storm feedback loop —
  writeback-lag→evict→FUA-storm→slower — catches a RANDOM subset of nodes each run). Makes single-run
  A/B UNRELIABLE. Need multiple fresh resets per data point, or a variance-robust metric (agg ops/s).

### PROBE BUILD D1E1911C (deployed) — keep for next session
- param `read_attr_probe` (default 0): (a) RD-ATTR counters at xfs_buf_submit_bio (WRONG path — storm
  is FUA via mxfs_buf_read_fua, bypasses submit_bio, counts ~0); (b) STALE-INO counter + ratelimited
  dump_stack at xfs_buf_stale for inode bufs (THE useful one — gave the staler above). mxfs_rd_*,
  mxfs_stale_ino atomics in xfs_mxfs_dlm.c. Turn OFF for perf runs.
See [[caw-sess5-32node-fresh-baselines-and-fua-read-root]] [[caw-32node-dlm_scaling-FIX-progress-and-fable-design]].
