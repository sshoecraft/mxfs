---
name: sess59-drc-root-grantless-readdir-async-evict-latency
description: sess59 PROVEN: dir_reuse 4-node readdir-miss root = grant-less NL readdir depends on ASYNC heartbeat eviction-ring DIR_MODIFY to trigger reload; at c…
metadata:
  type: project
---

## sess59 — PROVEN root cause (RULE 4) of dir_reuse_coherency 4-node readdir-miss

### Mechanism (3 independent lines of evidence)
1. **P62 probe** (reader test1, missing node4_f45.md5): in-core dir
   `incore_size=8192` vs `disk_size=12288`, `incore_gen==disk_gen`. Disk
   HAS the entry's 3rd data block; reader's in-core fork lags at 2 blocks.
2. **xfs_dir2_readdir.c:638** — readdir triggers `mxfs_dlm_reload_inode`
   ONLY if `MXFS_IF_DIR_RELOAD` flag set OR `i_dlm_dir_gen > i_dlm_dir_loaded_gen`.
   The reload (xfs_idestroy_fork + xfs_inode_from_disk) WOULD adopt disk 12288 —
   but BOTH trigger conditions are delivered solely by the ASYNC eviction ring
   (mxfs_dlm_evict_inode_cb, run by the disklock HEARTBEAT MONITOR thread).
3. **Transient/concurrent**: a grant-less NL reader doing readdir on a SHARED
   dir takes NO DLM grant (never BAST'd — producer comment xfs_mxfs_dlm.c:12707).
   At concurrent barrier-release, the peer's DIR_MODIFY for the final
   block-growth hasn't been delivered yet → neither trigger true → readdir
   enumerates stale in-core size (8192) → misses trailing-block entries.
   ~1s later the HB delivers it → reload → correct. Sequential reads
   (drc4_repro v1, 1s stagger) = 20 rounds CLEAN; concurrent reads = FAIL r9.

This is an EVENTUAL-CONSISTENCY gap in grant-less dir reads → FAIL by
[[feedback_timing_is_failure]] (coherency must be prompt ~ms).

### Obvious fixes ALREADY REFUTED (do not repeat)
- Tighten heartbeat/DIR_MODIFY latency: [[sess-tcp-heartbeat-reduction-insufficient]]
  — 500ms WEDGES, 1000ms only ~1/3 clean. NOT the fix.
- Per-readdir disk poll on all dirs: sess38/91 perf regression (explicitly
  warned against, xfs_dir2_readdir.c:613). Must stay event-driven for solo dirs.

### Candidate fix directions (untried this session)
- **A (preferred):** gated SYNCHRONOUS dir-version check at readdir entry, ONLY
  for multi-node + contended dirs (i_dlm_dir_gen>0) — same gating as
  mxfs_dlm_dir_durable_signal so solo rsync (gen=0) pays nothing. One cheap
  FUA dinode read; if disk di_size/di_gen != in-core → reload. RISK: durability
  ordering — the dinode di_size change may be in log/AIL not yet in-place on the
  platter when FUA-read (sess48/82 family); needs verification that the writer's
  durable_signal makes the DINODE (not just data blocks) in-place before signal.
- **C:** readers acquire a real PR grant for readdir on shared dirs (correct
  clustered-FS coherency) — heaviest perf, RULE-0 risk.

### Significance / strategy
Transport-INDEPENDENT (eviction ring used on TCP and CAW) → this IS the CAW
cache_coherency ship-blocker family (sess79-92). Fixing it here carries to CAW.
Prior obvious fixes refuted + sharp perf constraint → may meet RULE-5 consult
bar AFTER trying ≥1-2 distinct fixes. Repro: tests/tcp/drc4_repro.sh 4 50 24
(concurrent reads, fails ~round 9). See
[[sess59-drc-readdir-miss-stale-disksize-gen-equal]],
[[sess59-4node-tcp-16of17-dir-reuse-coherency-fails]].
