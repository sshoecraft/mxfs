---
name: AAA-ccloopa864-sess5-COMPREHENSIVE-STATE-multihead-wedges
description: sess5 COMPREHENSIVE: dir_reuse@32/caw has 3+ NON-DETERMINISTIC wedges (bmbt-bwrite-lost-wakeup / acquire-starvation / hard-hang-spinlock). Probe buil…
metadata:
  type: project
---

# sess5 (ccloop a864) COMPREHENSIVE STATE — dir_reuse@32/caw is MULTI-HEADED

## CRITERIA: only gap = dir_reuse_coherency@32/caw (all other caw tests pass at 1/2/4/8/16/32; dir_reuse passes 2/4/8/16). Everything below is that ONE cell.

## THREE NON-DETERMINISTIC WEDGES (a run hits ONE of them, varies run-to-run)
All are manifestations of 32-node single-hot-dir (ino=131) create+rmrf+verify contention. dir_reuse PASSES at 16, tips over at 32.

### Wedge #2a — durable-signal bmbt bwrite LOST-WAKEUP (proven, build E5F760E6)
rank1 rm stuck ~200s: `mxfs_dir_bmbt_scan+0x34f → xfs_bwrite → xfs_buf_iowait` (xfs_mxfs_dlm.c:772), via mxfs_dlm_dir_durable_signal (per-unlink, xfs_inode.c:4326). **inflight=0 on ALL devices** (dm-1/sda/sdb) — bio never submitted OR completion lost. LONE task (no bast kworkers, xfsaild running) → NOT sess4's AIL-jam. multipath healthy, no SCSI errors. owner_scan writes SUCCEED just before → intermittent RACE in the mxfs-custom buffer completion (pal/linux/xfs_buf.c). The durable_signal is LOAD-BEARING (xfs_inode.c:4302-4324: unpins dir buf so next modify doesn't RMW-clobber a peer = the P-COUNTREGRESS lost-update) — CANNOT just skip it.

### Wedge #3 — acquire STARVATION (this run, probe build 0349484E)
All nodes stuck at r6 create-start, P138-WAIT ino=131/132 mode=5(EX) elapsed climbing to 40s+, round not advancing. `stat`/`rm` D-state in mxfs_dlm_ilock_begin (DLM acquire). sess4 proposed caw_fair_handoff=1 BUT that's unsafe (see hard-hang). Shared-dir EX lock contended by 32 nodes; some starve past the 120s barrier.

### Hard-hang — reproducible SPINLOCK DEADLOCK (separate, config-INDEPENDENT)
test32 (run1 workload) + test27 (run3 prep) hard-hung IDENTICALLY: one vCPU busy-spinning (offset 0x116553F from idle, KASLR-invariant), others HALTED, RCU-stalled, net dead ("No route to host", virsh=running). Corrupted/leaked spinlock (use-after-free under reuse churn). Happens in DEFAULT config too (not fair_handoff-specific). Capture: all 32 nodes have `unknown_nmi_panic=1` drop-in (/etc/sysctl.d/99-mxfs-nmi.conf) → `virsh inject-nmi <node>` → panic stack to /var/log/libvirt/qemu/<node>-serial.log. NMI watchdog unavailable (no PMU, nmi_watchdog=0). See memory ...HARDHANG-reproducible-spinlock-deadlock.

## BUILD STATE
- **0349484E48664B480423690 (VERSION 0.10.51) = build in tree NOW** = E5F760E6 (orphan fix, KEEP) + P-IOWAIT-STUCK probe. Probe: pal/linux/xfs_buf.c xfs_buf_iowait — wait_for_completion_timeout(4s) loop logging daddr/ops/flags/err/wr_counted/lseq/wseq/done/dir_inflight when a sync I/O stalls >4s. FIRES on wedge#2a (not #3). Deployed cluster-wide this run but this run hit wedge#3 so probe didn't fire.

## PROVEN DEAD ENDS
- durable_caw=0 (+fair_handoff=1): hard-hang + P-COUNTREGRESS silent lost-update. DO NOT SHIP. (run.sh budget comment + this sess).
- fair_handoff=1: coincided with a hard-hang; also historically livelocks (sess130). Risky.

## NEXT (RULE 4)
1. **To catch wedge#2a root**: re-run build 0349484E; if it hits the bmbt-bwrite hang, grep `P-IOWAIT-STUCK` on rank1. Decisive fields: wr_counted=0 → no bio issued (skip-emulate no-complete path in xfs_buf_submit reinit'd b_iowait@5381 but never completed it); wr_counted=1 & dir_inflight>0 → counted bio never decremented (lost decrement at __xfs_buf_ioend:1433). Then fix that exact path.
2. **Wedge#3 (starvation)**: needs a fairness fix that does NOT hard-hang. Investigate the acquire path (caw_wait_for_grant, mxfs_dlm_ilock_begin) for why a waiter starves 40s. Maybe acquire-aging without full fair_handoff.
3. **Hard-hang**: next occurrence, inject-nmi BEFORE power-cycling → get the spinlock caller from serial log → fix the lock-lifetime bug (likely dlm_caw.c slot freed+reused).
4. Runs are non-deterministic — may need to run several times to hit a specific wedge.

## HARNESS / MECHANICS
- run.sh convergence gate PARALLELIZED this sess (was serial 32-SSH → false PREP FAIL at N=32; now converges in 6-9s). KEEP.
- Diagnostics in tree: tests/drc_wedge_capture.sh <node> (soft-wedge: rm/xfsaild/bast stacks+probes), tests/drc_hardhang_capture.sh <node> (inject-nmi+serial), tests/drc_progress_watch.sh.
- Wedge detector false-triggers on SLOW-but-progressing (36s rm) — confirm permanence by checking round advance + P138 elapsed climbing over 2 snapshots before declaring wedge.
- Device MXFS_DEV=/dev/mapper/mpatha. Budget dir_reuse@caw=140*N=4480s@32. Never rebuild while a run is active.
