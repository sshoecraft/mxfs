---
name: sess-tcp-13of16-pass-3-fails-blockalloc-partition-next
description: MILESTONE build AFC07F4D: full ./run.sh 2 tcp = 13 PASS / 3 FAIL / 0 PENDING. All 8 PENDING tests ported+pass except fence_during_write (false-positi…
metadata:
  type: project
---

## MILESTONE (build AFC07F4DC5E9EE12FFD101B): full `./run.sh 2 tcp` = 13 PASS / 3 FAIL / 0 PENDING
All 8 previously-PENDING tests are now PORTED (tests/suite/*.sh + tests/tcp/tcp_dlm_scaling.sh)
and 5 of them PASS: dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency,
fault_netpartition. Plus the original 7 coherency tests + soak infra.

### Two fixes landed this session (KEEP):
1. **Non-CAW disklock slot claim** (dlm/disklock.c mxfs_disklock_claim_slot_noncaw) — LIO LUN
   rejects the CAW (sense 0x5/0x24) so both nodes defaulted to slot 0 → both alloc in AG0 →
   inobt corruption. Now nodes get unique slots 0/1. Fixed dlm_fairness. (+v5_mount.c SCSI PR
   register [no-op on LIO] + node_id fallback.)
2. **Strict inode-AG partition** (xfs/libxfs/xfs_ialloc.c mxfs_ag_inode_owned + xfs_dialloc
   partition_relaxed pass): each node allocs INODES only in its AG stride (agno % L == slot % L,
   L=m_mxfs_log_node_count=4); relaxed fallback on partition-ENOSPC. Eliminated the cross-node
   inode double-alloc in shared spillover AGs.

### 3 remaining FAILs:
- **fence_during_write** (1/2): FALSE POSITIVE. node1 6/7 checks pass; the dmesg fence-pattern
  `fence|evict|...` matched 21 benign `EVICT-RING-DIRMOD` lines (normal eviction-ring). FIX:
  narrow FPAT in tests/suite/fence_during_write.sh to real fence/shutdown phrases only
  (drop bare `evict`/`fence`; keep `self-fence|Shutting down|Corruption|Internal error|fenced node`).
- **soak** (3458/4703 errs, dmesg_hits=0) and **tcp_dlm_scaling** (node1 got=0 rounds): both ran
  LATE and node1's FS was WEDGED by then. dmesg: `xfs_inactive_ifree → imap_to_bp -5 → Metadata
  I/O Error Shutting down` on ino in **agno=4 (node1's OWN partition AG)**; test2 same in agno=1
  (its own). Flood of `INACT-SKIP-STALE incore_mode=0100644 disk_mode=00` = live in-core inode but
  on-disk FREE. Since inode alloc is now partitioned (no inode-vs-inode cross-AG), the remaining
  vector is **DATA-BLOCK allocation is NOT partitioned** (xfs_bmap_btalloc/xfs_alloc_vextent use
  parent locality + unconstrained for_each_perag_wrap) → a cross-node DATA block gets allocated
  over an inode cluster → zeroes it on disk → disk_mode=00 → double-free-guard → shutdown
  (the sess55 dir/data-over-inode-cluster family).

### NEXT SESSION:
1. Fix fence_during_write FPAT (trivial → 14/16).
2. Partition DATA-BLOCK allocation the same way as inodes (constrain xfs_alloc AG selection to the
   node's owned stride agno%L==slot%L, relaxed fallback). Look at xfs_alloc.c xfs_alloc_vextent_*
   / xfs_bmap_btalloc args->fsbno/min/max agno. RISK: core allocator. This should fix soak +
   tcp_dlm_scaling (the FS won't wedge). Then re-run full suite for 16/16.
Cluster: both nodes' FS shut down (EIO) at suite end — needs reset/reboot. See
[[sess-tcp-FIX-noncaw-slot-claim-unique-ags]] [[sess-tcp-residual-spillover-doublealloc-cumulative]].
