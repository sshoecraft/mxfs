---
name: sess69-heartbeat-stale-read-false-eviction-fix
description: sess69 FIX (build FE603677): dead-detector evicted live peers off a stale PLAIN heartbeat read; added FUA confirm-before-evict (P-HBFALSE). Verifying.
metadata:
  type: project
---

## sess69 candidate fix — build FE6036776397D935E906E96 (UNVERIFIED, verifying now)

### Root (code-confirmed, RULE 4 proof pending from P-HBFALSE log)
zsl(16)/posix_multi16 verify-hang root = **spurious heartbeat evictions of LIVE
nodes** under storm → expensive `purge_node` (65536-slot FUA scan) + XFS journal
replay → dir-ilock starvation → `find` verify hangs (see
[[sess69-zsl-heartbeat-eviction-cascade-blocks-verify]]).

Why spurious: `disklock.c` heartbeat thread WRITES its own beat with
`write_sector_fua` (FUA) but the dead-detector MONITOR reads each peer's slot with
**plain `mxfs_pal_bdev_read`** (disklock.c:343) — cacheable. Under storm the guest
block layer / SCST per-initiator cache returns a STALE heartbeat sector, so a
live-but-busy peer's `timestamp_ms` looks frozen → `equal_samples` hits
`dead_threshold` (~31) → false eviction. This is the codebase's signature
FUA-read-coherency gap, in the dead-detector. (Every other coherency-critical read
uses `mxfs_pal_bdev_read_prio` → kernel `mxfs_scsi_read16_fua`, cache-bypassing.)

### Fix (dlm/disklock.c, confirm-before-evict)
At the eviction decision point (`if equal_samples>=dead_threshold && live`), BEFORE
firing dead, do a FUA cache-bypassing re-read via `mxfs_pal_bdev_read_prio`. If the
heartbeat actually advanced (`rhb->timestamp_ms != nt->last_timestamp`), log
`P-HBFALSE slot=.. last_ts=.. fua_ts=.. eq=..` and DO NOT evict (reset
equal_samples, adopt fresh ts). Epoch-change reboots reach `fire_dead:` via goto and
correctly SKIP the confirm (definite restart). Added `int crr;` decl at top of the
monitor for-loop (avoids goto-skips-init). This both PROVES the staleness (P-HBFALSE
firing = plain-stale/FUA-fresh) and FIXES the false-eviction cascade in one cycle.

### Verify recipe
- All 16 nodes load FE603677 (`cluster_reset_n.sh 16`; NOTE the verify step races —
  a different random node shows NOT_LOADED each run; re-prep stragglers, all do load).
- INFRA FLAKINESS THIS SESSION: parallel 16-node `reset4.sh` mount is unreliable
  (1 random node fails / nodes drift NOMNT) due to single-shared-LUN contention — but
  NO evictions/shutdowns at idle (fix is stable). zsl re-forms the cluster itself, so
  run it directly: `bash tests/criteria/zero_silent_loss.sh`.
- PASS = total_fs_silent=0 AND completed=3/3, no verify hang. Grep dmesg for
  `P-HBFALSE` (proof fix fired) vs real `no longer responding` evictions.
- If P-HBFALSE fires a LOT (every sample near threshold), follow up by converting the
  PRIMARY monitor read (disklock.c:343) to `mxfs_pal_bdev_read_prio` so the detector
  never accumulates stale samples (cheaper than confirm-every-time).
- If zsl PASSES, also re-run posix_semantics_multi16 (likely same root) + the full
  verify_ship.sh. Remaining separate roots: fence_during_write (lost=400, write-side
  durable lost-update), rsync_paired (148% perf).

Links: [[sess69-zsl-heartbeat-eviction-cascade-blocks-verify]] [[sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge]] [[sess18-crash-consistency-PASS-foreign-replay-shipped]]
</body>
