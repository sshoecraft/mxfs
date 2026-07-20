---
name: compiled-sess45-cache-coherency-uv-dir-read-cache-staleness
description: sess45: cache_coherency uv fail PROVEN = node1 dir-block READ cache staleness; suite at 14/17 (build EF006296).
metadata:
  type: project
tags: [compiled, cache_coherency, dir-read-staleness, sess45, dlm, tcp, unlink_visibility]
---

## sess45 — cache_coherency `uv` (unlink_visibility) root: node1 dir-block READ cache staleness

Central finding: the historical `cache_coherency` ship-blocker's `uv` sub-failure is **reader-side
dir-block cache staleness on node1** — NOT node2 durability, NOT the MODIFY path. Proven by A/B
discriminator, root-chained to the DLM/gen-bump path, with two candidate fixes handed to the next
session. Same class likely covers `dir_reuse` leaf-hash. Build/ccloop context: ccloop `8ddb16a2`,
build **EF006296** (known-good 14/17 baseline, `force_block=0` kept).

### Suite milestone — full `./run.sh 2 tcp` = 14 PASS / 3 FAIL (was ~8/17 in sess44)
Recovery from contaminated/wedged to 14/17 came from the partial-iwrite fix
([[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]], KEEP — confirmed by
`crash_consistency` passing in-suite). See [[sess45-MILESTONE-full-suite-14of17-three-remaining]].
- PASS (14): precond_readiness, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss,
  dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency,
  fence_during_write, fault_netpartition, soak.
- FAIL (3), ALL on node1/test1, all dir/visibility/perf coherency, no mid-suite cascade:
  1. **cache_coherency** 1/2 — `uv gone node2_file21..30` + `uv none remain(exp=0 got=10)`; node1
     sees the LAST 10 of node2's 30 just-unlinked files still present after the uv_delete MQTT
     barrier. Deterministic (same 10 standalone + full-suite). node2 PASSES. 190/201. No shutdown.
     Dir under test = `$MNT/.cache_coherency/unlink_visibility` ($D).
  2. **dir_reuse_coherency** 1/2 — `drc r1 r1 leaf-hash lookup_fail(exp=0 got=1)`; readdir lists a
     name but lookup ENOENTs (dir LEAF hash block missing an entry; sess19/20/26 leaf-hash-hole
     family; P56-LEAF probes at pal/linux/xfs_buf.c:2286+). 144/145. No shutdown.
  3. **tcp_dlm_scaling** 1/2 — `tds node1 completed rounds(exp=150 got=41)`; node1 SHUT DOWN mid-test
     via `__xfs_trans_commit+0x2c4 Corruption of in-memory data (0x8)` at xfs_trans.c:890 (uptime
     548s). A real in-memory-corruption-on-commit bug, not pure slowness. Separate from the dir-read
     class.

**GOTCHA (cost a false 0/17):** if a prior full-suite run is TaskStop'd mid-prep, the next full run
reports 0/17 — a false cascade (early DABUF_MAP_HOLE / trans_cancel on contaminated state). ALWAYS
reboot both nodes clean (`virsh destroy/start`) before trusting any full-suite result. The
`DABUF_MAP_HOLE` (xfs_create→xfs_dabuf_map !MAP_HOLE_OK, dir extent-map hole) did NOT recur on a
clean run — contamination artifact, not a standalone bug.

### PROVEN root (RULE-4 A/B discriminator) — reader-cache staleness, not node2 durability
See [[sess45-PROVEN-cachecoherency-uv-is-node1-dir-read-cache-staleness]]. Reliable repro: reboot
clean, `./run.sh 2 tcp cache_coherency` → node1 FAIL 1/2. Added an env-gated `MXFS_UV_DISCRIM=1`
branch to the uv check, ran, then REVERTED it:
`mxfs-UV-DISCRIM rank=1 peer=node2_file21 before=present after_dropcaches=gone`
— node1 saw the file present, then `sync; echo 3 > drop_caches` made it GONE. DECISIVE: node1's
page/buffer cache was stale; node2's unlink IS durable on the LUN. (Side effect: with the
discriminator ON, the test PASSED 2/2 because drop_caches refreshed node1 before the `ck` — further
proof of pure reader-cache staleness.)

### Mechanism / root chain (all proven this session)
node1's `test -e` → `xfs_lookup` reads $D's dir DATA block from cache without re-validating vs the
LUN. The dir-block coherency hook — `xfs_da_read_buf` invalidates a cached block when
`b_mxfs_dir_gen < dp->i_dlm_dir_gen` — is INERT because `i_dlm_dir_gen` bumps ONLY on a SLOW-PATH
dir DLM re-acquire (xfs_mxfs_dlm.c:9294, S_ISDIR). node1's lookup igets/locks with `lock_flags=0`,
so it skips the DLM acquire + gen bump → never invalidates → serves node2's pre-delete dir image.

Two independent gaps keep node1 stale (see
[[sess45-cachecoherency-uv-evictring-dedup-and-async-heartbeat-gap]]):
- **Gap 1 — lookup skips the DLM (no synchronous BAST invalidation).** `xfs_lookup`/`test -e` reads
  with `lock_flags=0`, holds no dir per-inode DLM lock, so node2 taking EX on $D to delete does NOT
  BAST node1. `mxfs_dlm_dir_modify_refresh` (xfs_mxfs_dlm.c:2627) only runs from MODIFY ops
  (xfs_create/remove/rename), never from pure lookups.
- **Gap 2 — async fallback (disklock evict-ring DIR_MODIFY) is lossy + too slow.** node2's deletes
  call `mxfs_disklock_note_freed(ino=$D, type=DIR_MODIFY)`. The producer DEDUPS
  (disklock.c:1037-1043): if the most-recent STAGED entry matches (ino,type) it skips — even after
  that entry was already published+consumed. So node2's 30 deletes stage essentially ONE DIR_MODIFY;
  node1 consumes it once (heartbeat-paced, async) → refreshes to a MID-burst snapshot (~after 20
  deletes) → bumps gen once → reads that snapshot for deletes 21-30 (the observed 20-gone/10-present).
  Even removing the dedup, heartbeat delivery lags the fast MQTT barrier → node1 can check before the
  last DIR_MODIFY arrives. Evict-ring is eventually-consistent; the criterion needs prompt (~ms)
  consistency ([[feedback_timing_is_failure]]).

### d_revalidate is active but insufficient (fix-entry chain)
See [[sess45-cachecoherency-uv-drevalidate-fastpath-no-reload-FIX-ENTRY]]. `sb->s_d_op =
&mxfs_dentry_operations` IS ACTIVE (pal/linux/xfs_super.c:2303) — the "sess38 DISABLED" note is
superseded by a later "sess45 RE-ENABLED"; that comment's "node-affine cheap gating" is STALE. The
real `mxfs_drevalidate` (xfs/xfs_mxfs_dentry.c:42) does a FULL revalidate for every multi-node
dentry: takes `xfs_ilock(dp, XFS_ILOCK_SHARED)` then `xfs_dir_lookup`, returns 0 (drop dentry) iff
the name no longer resolves. For uv, node1's positive dentry for node2_file21 is revalidated, but
`xfs_dir_lookup` reads node1's STALE cached $D data block (still lists the file) → resolves →
returns 1 (valid) → `test -e` finds it → FAIL. Why SHARED doesn't refresh: node1 cached a DLM PR
grant on $D during the pre-delete `ls` (uv check 68); node2's EX deletes SHOULD BAST that PR so
node1's next SHARED is slow-path (reload + `i_dlm_dir_gen++` + dir-block invalidate), but node1's
`xfs_ilock(SHARED)` FAST-PATHS on the still-cached grant → no reload. Either node2's EX isn't
BAST-downgrading node1's PR, or node1 re-grants fast without reloading.

### Reader-side fix locus (final lead before relay)
See [[sess45-uv-fix-locus-consumer-refresh-xfs_inode-695]]. `mxfs_dir_force_evict` ALREADY defaults
to 1 (xfs_mxfs_dlm.c:1995), so the MODIFY-path unconditional evict
(`mxfs_dlm_dir_modify_refresh`, 2627→2668 fall-through) is ON, yet uv STILL fails ⇒ the fix is NOT
the modify path; it's the READER path (consistent with sess10: force_evict didn't fix the
lost-update). Note force_evict fires on node1's OWN rm of node1_file*, capturing node2's state at
that moment (possibly mid-burst); node1's later `test -e` READS don't re-evict → reads a
mid-node2-burst snapshot. Reader refresh entry point: `mxfs_dlm_dir_consumer_refresh(dp)`
(xfs_mxfs_dlm.c:2470), called from xfs_inode.c:695 (a read/lookup path — likely xfs_dir_lookup or
xfs_readdir wrapper); runs with NO ILOCK, takes ILOCK_SHARED. It is almost certainly gated on
`(new_incarn || i_dlm_dir_gen != evicted_gen)` and that gate is FALSE for node1 (its `i_dlm_dir_gen`
for $D never advanced). NEXT: read `mxfs_dlm_dir_consumer_refresh` (2470-2560); candidate fix —
when multi-node and dir is peer-shared, FORCE the data-block evict (like dir_force_evict does for
the modify path) so node1's lookup cold-reads $D.

### FIX DIRECTIONS (next session — RULE-4 instrument before patching; RULE-0 perf watch vs tcp_dlm_scaling)
The correct mechanism is the SYNCHRONOUS DLM, not the async ring:
- **(a) LOAD-BEARING:** make node1's dir lookup acquire the dir per-inode DLM (PR) so node2's EX
  BASTs it → node1 invalidates + slow-path reloads (gen bump → `xfs_da_read_buf` re-reads). Cost:
  per-lookup DLM round-trip (watch tcp_dlm_scaling perf; sess38 disabled per-lookup refresh for CAW
  perf, but TCP reads are coherent under `fua_disable`, likely cheaper) + deadlock review (why
  lookups historically used lock_flags=0). Equivalent read-time option: in `mxfs_drevalidate` /
  `xfs_da_read_buf`, for a positive dentry in a multi-node peer-owned dir, bump `i_dlm_dir_gen` (or
  `xfs_buf_stale` + clear XBF_DONE on $D's cached data blocks) to force a scoped drop_caches-equiv +
  FUA re-read.
- **(b) cheaper partial:** relax the evict-ring dedup to not drop an event whose prior identical
  entry was already PUBLISHED (stage a 2nd entry for the burst tail). SAFE (ring overflow just makes
  the peer do a full sweep) but does NOT close the heartbeat-latency race alone.
- **(c) proactive:** on EVICT-RING-DIRMOD arrival for $D, invalidate node1's cached $D dir DATA
  blocks / bump gen.

HIGH RISK: dir-lock changes could regress the 14 passing tests — instrument first. Likely also fixes
`dir_reuse` leaf-hash lookup_fail (same dir-read-staleness class). VERIFY:
`./run.sh 2 tcp cache_coherency` (node1 must stop seeing node2_file21..30), then full `./run.sh 2 tcp`
for a clean 15+/17. tcp_dlm_scaling trans_commit corruption(0x8)@xfs_trans.c:890 is a separate bug.
