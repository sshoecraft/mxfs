---
name: sess44-unlink-latency-fixes-and-pr-wedge
description: sess44: dir-gen fresh-read stamp → mkdir+touch PASS cold; P137/P138 proved per-unlink sleeps; settle fixes built D9D22CF3 UNDEPLOYED — stale SCSI PR…
metadata:
  type: project
---

## Session 44 (ccloop 14d31183) — status at relay

### Landed + VERIFIED on cluster (build C6DF0D70..2C9BEB06 line)
1. **dir-gen fresh-read stamp** (xfs/libxfs/xfs_da_btree.c, v0.5.6): the coherency
   hook stamped `b_mxfs_dir_gen` ONLY in its invalidate branch; cache-miss/-ENOENT
   and fence-invalidated (!XBF_DONE) reads stayed gen=0 forever → false
   DIR-STALE-SKIP + a doubled FUA re-read per cold dir block. Fix: stamp on true
   miss (post-read, `dir_stamp_fresh` + `dir_gen_snap` snapshot) and on !DONE
   in-core (pre-read). RESULT: cold 16-node `--phase cluster`:
   **test_concurrent_mkdir PASS, test_concurrent_touch PASS** (yesterday's
   blockers, sess43). Remaining cluster-phase FAILs exposed behind them:
   concurrent_write (1/20, 4 nodes), discovery (14/16 markers),
   rename_vis_dbg (node16's WHOLE 20-file batch: created OK, `rv_create` barrier
   OK, then its own `mv` got ENOENT on all 20 — wholesale dirent-batch loss),
   rename_visibility (7–247/960 varying); sequential_consistency/tcp_mesh/
   unlink_visibility never ran (590s timeout). NOTE: yesterday's run died earlier
   (at cross_write_read), so these are NOT regressions — newly reached territory.

2. **P137/P138 latency decomposition (PROVEN, RULE 4)**: cleanup `rm` storms are
   the 600s-budget eater. Cross-node unlink was 53–70ms vs native <1ms; live stack
   sampling + stage timers attributed it:
   - `xfs_inactive_ifree`: msleep(10) settle + drain msleep(10) ≈ 22ms of 25ms
     (P137-INACT-TIME/P137-IFREE-TIME, force_us≈11.7k drain_us≈12.0k).
   - holder `bast_process` release: **msleep(20)** sess29 settle ≈ 20ms of 22.5ms
     (P138-BAST dur_us≈22.5k; P138-WAIT waiter total ≈24ms; UDP BAST delivery is
     FAST, ~1-2ms — not the problem).
   - local rm after ifree fixes: 4.8ms/file; cross-node 35-42ms (migration-bound).

### Built, NOT yet deployed/verified: build `D9D22CF3B3B61BB19D1C52A`
3. **settle fixes** (same proven mechanism both sites): the sess29 async CIL→AIL
   race is closed deterministically by pincount — per-item AIL-insert happens
   BEFORE iop_unpin in xfs_trans_committed_bulk, so `xfs_ipincount(ip)==0` ⇒
   insertion done. Changes:
   - `mxfs_ail_drain_inode_sync` break needs `!in_ail && xfs_ipincount==0`; first
     16 iters poll usleep_range(500,1000) then 10ms (rescue thresholds preserved).
   - `xfs_inactive_ifree`: msleep(10)+2nd log force → bounded pin-wait poll.
   - `bast_process`: msleep(20) → bounded pin-wait poll (log_force(SYNC) precedes).
   - P138-BAST/P138-WAIT probes are always-on >5ms ratelimited (keep).
   EXPECTED: holder release ~3-5ms, cross-node unlink ~8-12ms. VERIFY with the
   20-file probe (test16 creates in /mnt/shared/probe16, test1 rms, read P137/P138)
   then run cold full phase.

### BLOCKER at relay: stale SCSI Persistent Reservation wedges mkfs
reset4 fails: test1 mkfs/mount get `reservation conflict` (error -52) on /dev/sda.
PR state on SCST (clyde, device `disk1`, /var/lib/scst/pr/disk1): reservation
held by key 0xaf6ceb8b, "Write Exclusive registrants only", 10 registered keys —
ALL from dead VM sessions (release attempt from every node rc=24). sg_persist
register-ignore reports rc=0 but the key does NOT appear in the key list, and
subsequent clear/preempt from that node still rc=24 → SCST seems to bind
registrations to I_T nexus identities the re-logged sessions don't match.
NEXT STEPS to clear (in order of preference):
 a) check how mxfs mount itself re-registers (dlm/ PR fencing code — it clearly
    coped before; maybe mkfs_mxfs needs a PR-clear flag or the mount does
    register-ignore THEN preempt with mxfs's own key derivation);
 b) destroy ALL 16 VMs (no initiators), then on clyde:
    `scstadmin -resync_dev disk1` after truncating/removing /var/lib/scst/pr/disk1
    (device must be suspended/resurrected for SCST to reread PR state) — do NOT
    reboot clyde (RULE 2), and beware the sess43 SCST suspend wedge;
 c) from a node, sg_persist --out --preempt-abort with --prout-type matching the
    existing type (5 = WE-RO) was already tried rc=24; try type 1 and omitting
    prout-type.
Cluster is otherwise healthy; nodes run D9D22CF3 module (loaded by
cluster_reset_n) but FS is NOT mounted anywhere (mkfs blocked).

### Infra notes (recurring)
- After `cluster_reset_n.sh`, /mnt/mxfs-src is an EMPTY mountpoint stub on nodes;
  run_tests.sh needs it: `mount --bind /src/mxfs /mnt/mxfs-src` on every node
  (NFS /src is auto-mounted via fstab; only the bind is missing).
- P138/P137 problems found via LIVE stack sampling (`/proc/PID/stack` repeatedly)
  — cheap and decisive; prefer before building instrumented kernels.
- rename_vis_dbg failure shape: barrier debug now prints dir_ino per barrier —
  barrier dirs differ per barrier (normal). node16's loss happened between its
  own create loop and its own rename loop, with rv_create barrier (lookup=1
  readdir=1) succeeding in between.

Related: [[sess43-dirdata-pin-rootcause]], [[sess43-scst-unwedge-and-p136]].
