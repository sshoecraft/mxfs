---
name: sess18-crash-consistency-PASS-foreign-replay-shipped
description: sess18: crash_consistency PASS ×3 (2+4 nodes). v0.5.0 foreign-slice replay shipped (build CB1C5FEF) + lease_timeout_ms param (old mxfs_lease_* never…
metadata:
  type: project
---

# sess18 — crash_consistency FIXED (PASS ×3), v0.5.0 foreign-slice replay complete

## Result (build `CB1C5FEF6D9B6C4CA094D29`, VERSION 0.5.0)
- crash_consistency PASS: --nodes 2 (123/123), --nodes 4 (110/110), --nodes 4 repeat
  (acked=106 visible=107). Wall 106-108s each; budget tightened 210→150s.
- Verified chain in dmesg: `lease_timeout_ms=16000` init echo →
  `dead-declaration window set to 16000 ms (8 samples)` → death detected at
  kill+16s (`after 8 checks`) → lowest-live-slot election → foreign replay of
  dead slice ~160ms → reader saw all fsync-acked records.

## What was implemented (completes sess17 design — see [[sess17-crash-consistency-root-and-foreign-replay-design]])
1. **Orchestrator** `mxfs_xlog_recover_foreign_slice(mp, dead_slot)` in
   xfs/xfs_log.c (decl xfs_log.h): private dummy AIL (kzalloc; xlog_find_tail
   writes ail_head_lsn), shadow xlog via xlog_alloc_log over the dead slice,
   XLOG_MXFS_FOREIGN_REPLAY bit, xlog_recover, dealloc.
   **Slice index = dead HB slot % m_mxfs_log_node_count** (mirror of
   xfs_mountfs) — passing the raw slot hit the >=node_count guard and silently
   no-op'd (first deploy bug). HB slots keep incrementing across re-mkfs
   (4-node run used slots 8-11, then 12-15), so the modulo is mandatory.
2. **xlog_dealloc_log guard**: only NULL mp->m_log if it owns it (shadow
   shares l_mp with the live mount).
3. **Election** `mxfs_disklock_lowest_live_slot(ctx, skip_slot)` (disklock.c):
   first live slot ascending incl. local_slot; runs in HB thread, no locks.
4. **Trigger**: v5_lease_expire_cb (after purges) → elected node only →
   `mxfs_v5_dlm_set_dead_node_notify` → xfs_mxfs_dlm.c handler sets bit in
   mp->m_mxfs_foreign_dead_slots (64-bitmap) + queue_work(system_unbound_wq,
   mp->m_mxfs_foreign_replay_work); work fn: peer_joined_flush → replay →
   peer_joined_flush. cancel_work_sync in xfs_super.c unmount + out_unmount
   paths (inside the m_mxfs_dlm blocks, after v5 shutdown, before unmountfs).
5. **lease_timeout_ms module param** (xfs_super.c) → v5_dlm_opts →
   `mxfs_disklock_set_dead_timeout_ms` (ms → samples at 2s HB interval, floor
   2). Default 0 = 31 samples = 62s (production).

## CRITICAL test-infra discoveries
- **`mxfs_lease_timeout_ms` / `mxfs_lease_duration_ms` module params NEVER
  EXISTED.** crash_consistency.sh passed them for ~all of history; insmod
  silently ignores unknown params. Death detection was always hardcoded
  31×2s=62s while the script slept only 60s → reader always checked before
  recovery. (sess17's "10s test leases caused false-fence storm" attribution
  is therefore WRONG — that storm ran at 62s detection; cause unknown, re-test.)
- **insmod on an already-loaded module fails File-exists SILENTLY and swallows
  INSMOD_OPTS.** cluster_reset leaves mxfs loaded; fresh_cluster_mount now
  rmmod-then-insmods (lib.sh, both first-node and rest-node blocks).
- init_xfs_fs now echoes `mxfs: lease_timeout_ms=%u` at every successful
  insmod — "after 31 checks" in a log where this reads nonzero = plumbing bug.
- crash_consistency.sh INSMOD_OPTS is now `lease_timeout_ms=16000`.

## Known design notes / accepted risks (documented, not bugs yet)
- Purge→election gap is ~13s (CAW+DLM purge inside v5_lease_expire_cb is slow)
  — total recovery kill→replay-complete ≈ 29s. Fine for the criterion (60s
  window); revisit if a tighter SLA appears.
- Cross-slice LSN gating in pass2 (xlog_recover_get_buf_lsn) compares
  incomparable per-node LSN spaces. Mitigated by flush-before-replay (our
  newer versions reach disk first) and by drain-pipeline invariant (dead node
  flushed before any unlock it granted). Same exposure exists in mount-time
  slice claim; predates this feature.
- A node joining and claiming the dead slot mid-replay could race the live
  replay's xlog_clear_stale_blocks writes. Window is seconds; criteria don't
  add nodes mid-test.
- Replay racing teardown returns -117 harmlessly if device is closing (seen
  once in run 3 when reply fired during cleanup unmount; cancel_work_sync now
  bounds it).

## Next (sess17 plan continuation)
- fence_during_write --nodes 4, scaling_curve, posix_semantics --nodes 16,
  crash_consistency at 16 nodes (watch for the false-fence storm — now with
  real 16s window), then full verify_ship.sh.
