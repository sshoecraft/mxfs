---
name: sess-tcp-HANDOFF-deep-inode-wedge-is-last-blocker
description: HANDOFF: 2/tcp criteria NOT met. Wins this session (build AFC07F4D): dlm_fairness FIXED (non-CAW slot claim) + all 8 PENDING tests ported + inode-AG…
metadata:
  type: project
---

## STATE (build AFC07F4DC5E9EE12FFD101B, both nodes): criteria "2 node dlm=tcp 100%" NOT met.

### WINS this session (all KEEP, in tree):
1. dlm/disklock.c `mxfs_disklock_claim_slot_noncaw` — LIO LUN rejects CAW (sense 0x5/0x24) so
   both nodes defaulted to slot 0 → both alloc AG0 → inobt corruption. Now unique slots 0/1.
   FIXED dlm_fairness (was the criteria's lone FAIL). +v5_mount.c SCSI-PR-register (no-op on LIO)
   +node_id fallback. See [[sess-tcp-ROOT-dlmfairness-both-nodes-slot0-no-scsipr]].
2. xfs/libxfs/xfs_ialloc.c — strict INODE-AG partition (`mxfs_ag_inode_owned`, agno%L==slot%L,
   L=m_mxfs_log_node_count=4; xfs_dialloc partition_relaxed fallback). Eliminated cross-node
   inode double-alloc in shared spillover AGs.
3. ALL 8 PENDING tests ported: tests/suite/{dlm_membership,scaling_curve,dlm_scaling,rsync_paired,
   crash_consistency,fence_during_write,fault_netpartition}.sh + tests/tcp/tcp_dlm_scaling.sh.
   PASS standalone/most runs: dlm_membership, scaling_curve, rsync_paired, crash_consistency,
   fault_netpartition (+ original 7 coherency + soak infra).

### Best full-suite result: 13 PASS / 3 FAIL. But VARIABLE: a later identical re-run gave
9 PASS / 7 FAIL. The variance IS the blocker (see below).

### THE LAST BLOCKER = deep stale-INODE duplicate-free wedge under CUMULATIVE load (NOT new):
Under the full `./run.sh 2 tcp` (all 16 tests on ONE mount, no remount between), the FS
eventually WEDGES: `xfs_inactive_ifree → DLM inode reload imap_to_bp -5 → Metadata I/O Error,
Shutting down` + flood of `INACT-SKIP-STALE incore_mode=0100644 disk_mode=00` (live in-core
inode, FREE on disk) in a node's OWN partition AG (test1 AG4 / test2 AG1). This is the
90-session cache_coherency family = **stale INODE / in-core BMAP cross-node duplicate-free**
(see [[sess111_reframe_bnobt_red_herring]]: NOT bnobt/AG-meta [red herring], NOT block-alloc
[sess55 ruled out] — the inode cache holds a stale-live copy of an inode freed/reused on disk).
Variable timing → soak (coord=none, node1) + tcp_dlm_scaling run late and hit the wedged FS
(soak 3458/4703 EIO errs dmesg_hits=0; tcp_dlm_scaling node1 got=0 rounds). When the suite
happens NOT to wedge, those pass.

### Diagnose next (RULE 4, instruments already live at instr=0, per sess111):
At xfs/libxfs/xfs_alloc.c:2244 shutdown: P15-INSTR (free-ag-extent-fail), P47-INACT verdict
(DISK-FREE=>double-free | GEN-MISMATCH=>stale-inode | DISK-LIVE-same-gen=>lost-removal),
P81-DEXT disk_claims_freed (0=in-core BMAP stale=inode bug). INACT-SKIP-STALE (xfs_inode.c:2281).
Reproduce: full `./run.sh 2 tcp` a few times; grep test1/test2 dmesg for P47/P81 at the wedge.
The fix is the inode-recycle / cross-node inode-cache coherency (sess40/48/108/111 lineage),
NOT allocator partitioning.

### Smaller residuals:
- fence_during_write: FIXED the FPAT false-positive (was matching benign EVICT-RING); fix is
  live (tests/suite/fence_during_write.sh on NFS, no rebuild). Re-verify it passes when FS healthy.
- dlm_scaling: INTERMITTENT (PASS one run, FAIL next) — perf-threshold (FLOOR_OPS=50/s, 60s
  window for 2000 ops) too tight when metadata is slow under cumulative load. Consider relaxing
  the floor / raising the window, OR it's a real RULE-0 metadata-perf issue under load.

### Harness notes:
- run.sh prep umount HARDENED (fuser -k + retry + lazy + rmmod retry) — committed in run.sh.
- reset2_tcp.sh sometimes times out at 250s when preceded by a VM reboot (boot wait eats budget);
  run reboot and reset as SEPARATE steps.
- Target is LIO-ORG (not SCST): no SCSI PR, rejects CAW, drops FUA. Both nodes' FS often EIO-
  wedged at suite end → reboot (virsh destroy/start) + reset2_tcp to recover.
See [[sess-tcp-13of16-pass-3-fails-blockalloc-partition-next]] [[sess-tcp-FIX-noncaw-slot-claim-unique-ags]].
