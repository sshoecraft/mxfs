---
name: sess45-cachecoherency-uv-evictring-dedup-and-async-heartbeat-gap
description: sess45 dir-read-staleness fix analysis: node1's lookups skip the DLM (no sync BAST), relying on the async disklock evict-ring DIR_MODIFY — which (a)…
metadata:
  type: project
---

## sess45 — WHY node1's dir-read stays stale (cache_coherency uv + dir_reuse leaf-hash), and the fix tension

Builds on [[sess45-PROVEN-cachecoherency-uv-is-node1-dir-read-cache-staleness]] (drop_caches proved
node1 cache-stale, node2 durable). The refresh path that SHOULD invalidate node1's cached $D dir
blocks has TWO gaps:

### Gap 1 — node1's LOOKUP skips the DLM (no synchronous BAST-driven invalidation)
`xfs_lookup`/`test -e` reads $D's dir DATA block from cache with lock_flags=0 — it does NOT acquire
the dir per-inode DLM, so node2 taking EX on $D to delete does NOT BAST node1 (node1 holds no lock)
→ node1 never drops/reloads. The read-time hook (xfs_da_read_buf invalidates when b_mxfs_dir_gen <
i_dlm_dir_gen) is inert because i_dlm_dir_gen only bumps on a SLOW-PATH dir DLM re-acquire
(xfs_mxfs_dlm.c:9294), which lookup never triggers. `mxfs_dlm_dir_modify_refresh` (xfs_mxfs_dlm.c:2627)
only runs from MODIFY ops (xfs_create/remove/rename), NOT pure lookups.

### Gap 2 — the async fallback (disklock evict-ring DIR_MODIFY) is lossy + too slow
node2's deletes call mxfs_disklock_note_freed(ino=$D, type=DIR_MODIFY). The producer DEDUPS
(disklock.c:1037-1043): if the most-recent STAGED entry is the same (ino,type), skip — EVEN AFTER
that entry was already published+consumed. So node2's 30 deletes stage essentially ONE DIR_MODIFY for
$D. node1 consumes it once (heartbeat-paced, async) → refreshes to a MID-burst snapshot (≈after 20
deletes) → bumps gen once → reads that snapshot for deletes 21-30 (the observed 20-gone/10-present).
Even removing the dedup, the heartbeat delivery lags the test's fast MQTT barrier, so node1 can CHECK
before the last DIR_MODIFY arrives → still stale. Evict-ring = eventually-consistent; the criterion
needs prompt (~ms) consistency ([[feedback_timing_is_failure]]).

### FIX DIRECTION (RULE-4, prove before patch; HIGH RISK — could regress the 14 passing tests):
The correct mechanism is the SYNCHRONOUS DLM, not the async ring. Make node1's dir lookup coordinate
with peer dir modifications so node2's EX synchronously invalidates node1:
  (a) dir lookup acquires the dir per-inode DLM (PR) so node2's EX BASTs it → node1 invalidates +
      slow-path-reloads (gen bump → xfs_da_read_buf re-reads). Cost: per-lookup DLM round-trip
      (watch tcp_dlm_scaling perf, RULE 0) + deadlock review (why lookups historically used
      lock_flags=0). This is the load-bearing fix.
  (b) cheaper partial: relax the evict-ring dedup to not drop an event whose prior identical entry
      was already PUBLISHED (stage a 2nd entry for the burst tail) — SAFE (ring overflow just makes
      the peer do a full sweep) but does NOT close the heartbeat-latency race alone.
Likely fixes BOTH cache_coherency uv AND dir_reuse leaf-hash (same dir-read-staleness class).
tcp_dlm_scaling is separate (node1 __xfs_trans_commit:890 in-memory-corruption shutdown ~round 41).
State: full suite 14/17 ([[sess45-MILESTONE-full-suite-14of17-three-remaining]]); crash_consistency
deep wedge FIXED ([[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]]).</body>
