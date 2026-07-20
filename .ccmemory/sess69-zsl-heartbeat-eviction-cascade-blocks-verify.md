---
name: sess69-zsl-heartbeat-eviction-cascade-blocks-verify
description: sess69: with host UNWEDGED, zsl(16) FAILs via heartbeat-eviction cascade under storm → slow 65536-FUA purge_node + XFS recovery starves find verify (…
metadata:
  type: project
---

## sess69 — first real zsl(16) run after host recovery: FAILS on eviction cascade, NOT silent-loss

After unwedging the host ([[sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge]]) and a clean
`cluster_reset_n.sh 16` + `reset4.sh 16` (all 16 loaded **2D460CA3**), ran
`tests/criteria/zero_silent_loss.sh` (defaults: 3 iters, dpn=100, mode=1).

### Result: FAIL (structural) — verify hang, killed at outer 520s (internal budget 480s)
Log `/tmp/zero_silent_loss.0yZS3C.log`: iter1 storm ran, then "node0 find hang"×3 →
"VERIFY HANG ... STRUCTURAL break, marking iter as loss"; iter2 started, then SIGKILL.
**Host did NOT re-wedge** (D-state 0, portal up, disk1 vdisk clean — sess68 sda
timeout=180 prevention held). So the failure is in the cluster, not SCST.

### Proven chain (sysrq-w stacks on test1 + dmesg)
- dmesg test1: `slot 7 (test8) no longer responding (heartbeat expired after 31
  checks)` → `P-H22-PURGE-NODE dead_slot=7` → `XFS (sda): Starting recovery`; then
  same for `slot 9`. **Cascade of heartbeat evictions under 16-node storm.**
- Keystone task `mxfs-worker` pid1200 state:D in
  `mxfs_dlm_caw_purge_node → mxfs_pal_bdev_read_prio → mxfs_pal_scsi_read_fua_bdev
  → io_schedule_timeout` (purging a dead node's locks via FUA reads).
- `mxfs_dlm_caw_purge_node` (dlm/dlm_caw.c:2810) **scans ALL 65536 slots, one
  `read_slot` FUA read each** (dlm_caw.md:103 confirms). 65536 FUA reads/purge over
  the contended single-LUN path = tens of s to minutes; cascade multiplies it.
- During purge+recovery node0 holds dir ilocks: `find` pid1435
  `xfs_readdir → xfs_ilock_data_map_shared → down_write` (EX) blocked; getattr finds
  (1449/1460/1471) `mxfs_getattr_dlm_lock → xfs_ilock → down_read` blocked behind the
  queued writer. All permanently D (etimes 535-648s). End state: only test1 still
  MNT; test2-15 NOMNT (unmounted for iter2 remount while node0 wedged).

### Why spurious evictions (hypothesis, not yet proven)
All 16 nodes' I/O funnels through clyde's single SCST disk1 vdisk = single /dev/sdd
(loopback iSCSI to disk1b). Under storm, heartbeat CAW writes queue behind data I/O →
>lease_timeout_ms (sess18 set =16000) → eviction. `samples = timeout_ms /
MXFS_DISKLOCK_HB_INTERVAL_MS` ⇒ ~31 checks ⇒ ~16s window (disklock.c:1060, :474).

### NEXT (RULE 4 — reproduce first, then attack root)
1. Clean `cluster_reset_n.sh 16` + `reset4.sh 16` (virsh destroy force-kills the
   D-state node0 — fine). Re-run zsl. Confirm cascade is deterministic vs cold-start
   one-off (MEMORY warns cold cluster gives SESS50-STARVE slow results).
2. If deterministic, two candidate roots to instrument (NOT patch blind):
   (a) **purge_node O(65536) FUA scan is too slow** — needs bulk/sequential read of
       the slot table (one big read, not per-slot FUA), or skip-scan via an active-slot
       index, so recovery doesn't hold locks for minutes.
   (b) **heartbeat too aggressive under storm** — heartbeat write I/O must be
       prioritized above storm data I/O so a live-but-busy node isn't falsely evicted.
       Do NOT just widen lease_timeout_ms (RULE 0 masks slowness + breaks
       crash_consistency 16s detect, sess18).
3. Reference: zsl PASSED at 355s on build 9C2D4FA6 (sess17) — compare what changed.

Links: [[sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge]] [[sess50-phantom-ex-waiter-recompute-rootfix]] [[sess68-host-loopback-deadlock-and-sharpened-p67-probe]]
</body>
