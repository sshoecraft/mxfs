---
name: compiled-tcp-inode-wedge-dlmfairness-suite-port
description: TCP-DLM port arc: non-CAW slot fix→dlm_fairness PASS, 8 tests ported to 13/16, deep stale-inode double-free wedge fixed by B4 no-authority guard.
metadata:
  type: project
tags: [compiled, tcp-dlm, inode-wedge, double-free, dlm-fairness, cache-coherency, allocator-partition]
---

Central topic: bringing the TCP-DLM transport to a 100% "2 node dlm=tcp" ship state. Three linked threads: (1) a slot-claim fix that unblocked dlm_fairness, (2) porting the 8 PENDING suite tests to reach 13/16, and (3) chasing the last blocker — a deep stale-inode duplicate-free wedge under cumulative load — down to a proven fix. Target is a **LIO-ORG** LUN: no SCSI PR (register = -EOPNOTSUPP, no-op), REJECTS COMPARE_AND_WRITE (sense 0x5/0x24 → CAW slot-claim never worked), drops FUA. Cluster is 2 nodes on slots 0/1.

## Build progression
- **A3E2842CCEF45CB87CF67FD** — non-CAW disklock slot claim. dlm_fairness PASS.
- **AFC07F4DC5E9EE12FFD101B** — +8 ported tests +strict inode-AG partition. 13/16 milestone; fast-repro of the wedge isolated.
- **B4168BB57ABD4ED3936F637** — B4 no-authority inactivation guard. Fast-repro wedge PROVEN fixed.
(Also referenced: F22321, an older both-slot-0 build where soak once passed the full suite — timing-dependent.)

## Fix 1 — non-CAW slot claim (root of dlm_fairness FAIL) [[sess-tcp-dlmfairness-PASS-via-harness-3of3]]
Because LIO rejects CAW, both nodes' CAW slot-claim failed and both defaulted to **slot 0 → both allocated AG0 → inobt freemask corruption → FS shutdown**. Fix: `dlm/disklock.c mxfs_disklock_claim_slot_noncaw` gives unique slots 0/1 → distinct preferred AGs. Plus `v5_mount.c` SCSI-PR-register (confirmed no-op on LIO, harmless, removable) + node_id fallback. Result: `./run.sh 2 tcp dlm_fairness` = PASS 3/3 (nodes_pass=2/2). repro_pm_loop 15× = 14 PASS / 1 got=1 (rare stale-readdir, partly a loop artifact — repro_pm_loop rm-rf's the shared dir between iters causing ABA stale-dir; run.sh mkfs's fresh each run so the harness path is clean). df_diag 20× = zero got=1.

## Fix 2 — strict inode-AG partition [[sess-tcp-13of16-pass-3-fails-blockalloc-partition-next]]
`xfs/libxfs/xfs_ialloc.c mxfs_ag_inode_owned`: each node allocs INODES only in its AG stride (`agno % L == slot % L`, L=`m_mxfs_log_node_count`=4); `xfs_dialloc` gets a `partition_relaxed` fallback pass on partition-ENOSPC. Eliminated cross-node inode-vs-inode double-alloc in shared spillover AGs.

## 8 PENDING tests ported [[sess-tcp-HANDOFF-deep-inode-wedge-is-last-blocker]]
tests/suite/{dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition}.sh + tests/tcp/tcp_dlm_scaling.sh. Reference sources were tests/cluster/*.sh. The "fault" ones (kill/fence/partition) were hardest; crash_consistency needs foreign-log-replay. PASS (standalone/most runs): dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fault_netpartition — plus the original 7 coherency tests + soak infra.

## 13/16 milestone and its 3 FAILs [[sess-tcp-13of16-pass-3-fails-blockalloc-partition-next]]
Best full `./run.sh 2 tcp` = **13 PASS / 3 FAIL / 0 PENDING**. But VARIABLE — a later identical re-run gave 9/7. The variance is itself the blocker. The 3 FAILs:
- **fence_during_write** — FALSE POSITIVE. node1 6/7 checks pass; dmesg FPAT matched 21 benign `EVICT-RING-DIRMOD` lines. Fix (live, no rebuild): narrow FPAT in tests/suite/fence_during_write.sh to real phrases only (`self-fence|Shutting down|Corruption|Internal error|fenced node`), drop bare `evict`/`fence`. → trivially 14/16.
- **soak** (dmesg_hits=0, e.g. 3458/4703 or 3766/4910 EIO errs) and **tcp_dlm_scaling** (node1 got=0 rounds) — both ran LATE, after the FS had already wedged; dmesg_hits=0 because the shutdown predated soak's marker. Not independent failures — collateral of the wedge.
- **dlm_scaling** — INTERMITTENT (PASS one run, FAIL next); perf-threshold FLOOR_OPS=50/s over a 60s window for 2000 ops is too tight when metadata slows under cumulative load. Possibly a real RULE-0 perf issue under load.

## The last blocker — deep stale-inode duplicate-free wedge
Under full `./run.sh 2 tcp` (all 16 tests on ONE mount, no remount between), the FS eventually wedges: `xfs_inactive_ifree → DLM inode reload imap_to_bp -5 → Metadata I/O Error, Shutting down`, plus a flood of `INACT-SKIP-STALE incore_mode=0100644 disk_mode=00` (live in-core inode, FREE on disk) in a node's OWN partition AG (test1 AG4 / test2 AG1 / earlier AG3). This is the ~90-session cache_coherency family (sess40/48/108/111 lineage): stale INODE / in-core copy of an inode freed+reused on disk — NOT bnobt/AG-meta and NOT block-alloc (both prior red herrings).

### Residual double-alloc via AG spillover [[sess-tcp-residual-spillover-doublealloc-cumulative]]
After the slot fix, individual coherency tests + dlm_fairness all PASS, but the cumulative full suite still failed soak. Mechanism: node-affinity (`xfs_dialloc_pick_ag`) sends each node's allocs to its OWN AG; under cumulative load that affine AG FILLS, so `for_each_perag_wrap_at` SPILLS into a shared/peer AG (AG3 seen) where both nodes allocate from the same inobt with stale cross-node views → double-alloc (`P82-ADD agno=3`, later `incore_gen != disk_gen` = peer reallocated) → shutdown. The slot fix removed the GUARANTEED AG0 collision; data-heavy cumulative load still spills+collides — the long-standing double-alloc family in a milder form. Constraints on partitioning: `m_mxfs_max_nodes`=64 (MXFS_MAX_NODES) > agcount=50, so can't partition by max_nodes — must partition by live-node count (dlm `active_nodes.count`, dlm.h:101). Caveat: an older build (F22321, both-slot-0) saw soak PASS in the full suite once → intermittent, load/timing-dependent.

### FAST REPRO (build AFC07F4D) [[sess-tcp-FAST-REPRO-wedge-and-classification]]
Reproduces in seconds, not the 8-min suite. On a clean 2-node tcp cluster, run on BOTH nodes concurrently in ONE shared dir (each node its own t${RANK}_* names):
```
D=/mnt/shared/.wedge; mkdir -p $D
for i in $(seq 1 3000); do : > $D/t${RANK}_$i; rm -f $D/t${RANK}_$i; done
```
test2's FS shut down in ~seconds — `xfs_inactive_ifree → Metadata I/O Error (xfs_inode.c:2374)` + 112 `INACT-SKIP-STALE` hits, in test2's OWN affine AG1 (slot1→AG1). **PURE METADATA churn, no data writes** → the wedge is NOT data-block-over-inode-cluster (a key elimination). The killer inode signature (proven by P19-B3DEC / P47-INACT): `disk_mode=0100644 (LIVE), disk_gen==incore_gen (MATCH), coh_nlink=0, local_unlink=0, dlm_mode=0 (NL), will_skip=0` with `b1_diskfree=0 b2_genmis=0 b3_tornlive=0`. All prior guard cases MISS it (B3 requires coh_nlink>0). = sess111 "DISK-LIVE-same-gen ⇒ A-lost-removal" class. Meaning: a node destructively inactivating a STALE CACHED copy of a peer's inode (instantiated via readdir/lookup of the shared dir, driven to nlink==0 by a peer-coherent reload) that the PEER actually unlinked and will free itself → `xfs_ifree` frees blocks the peer's on-disk inode still owns → inobt -117 → shutdown.

### Fix 3 — B4 "no-authority" inactivation guard (build B4168BB5) [[sess-tcp-B4-noauth-guard-fixes-fast-repro-wedge]]
xfs/xfs_inode.c ~line 2763, added to the INACT-SKIP-STALE condition (reason `no-authority-unlocked-not-unlinked`):
```
bool mxfs_b4_no_authority = !mxfs_local_unlink &&
    ip->i_dlm_mode == MXFS_LOCK_NL &&      /* hold no grant */
    mxfs_coh_nlink == 0 &&
    !xlog_recovery_needed(mp->m_log);      /* recovery gate */
```
A node with no local-unlink intent AND no DLM lock has no authority to free the inode; the unlinking peer (holds EX, local_unlink=1) frees it. **Recovery gate is essential**: at MOUNT-TIME iunlink log recovery the survivor MUST free a dead peer's orphaned inodes (also local_unlink=0 + NL + coh_nlink=0 by construction) — must NOT skip then. Note mxfs dead-peer recovery is `mxfs_journal_replay` (dlm/mount.c `recover_dead_node_journal`), NOT xfs_inactive; so the only legit xfs_inactive free-of-not-locally-unlinked is mount-time iunlink recovery. PROVEN: fast repro (2-node 3000 create+unlink storm ×4 rounds) → NO wedge, both nodes stayed mounted+writable; captured `ino=2100207 ... b4_noauth=1 will_skip=1` = the exact killer caught & skipped (previously test2 died in ~seconds on round 1). Known cost: a possibly-leaked inode if the unlinking peer dies AFTER we cache it AND after mount recovery already ran (rare) — a leak is fsck-recoverable, strictly better than a double-free shutdown. Watch crash_consistency for regressions.

## Open items / next
- Run full `./run.sh 2 tcp` (16 tests) on B4168BB5 to confirm the wedge is gone across the cumulative suite; expect soak + tcp_dlm_scaling to recover once the FS no longer shuts down.
- Apply the fence_during_write FPAT narrowing (→14/16) and re-verify it passes when FS is healthy.
- Reassess dlm_scaling perf floor (FLOOR_OPS/window) under load — could be RULE-0.
- Data-block allocation is still not partitioned (`xfs_bmap_btalloc`/`xfs_alloc_vextent` use parent locality + unconstrained `for_each_perag_wrap`); a strict data-block AG partition (owned(a)=a%N==slot%N, N=live-node count, relaxed fallback on true ENOSPC) is the candidate hardening but is a RISKY core-allocator change — confirm reproducibility before doing it.

## Harness / environment notes
- run.sh prep umount is non-forcing/backgrounded and flakes if a prior run left the mount busy (→ mkfs returns 1 → ABORT). HARDENED in run.sh (fuser -k + retry + lazy + rmmod retry). Between runs manually: `fuser -k /mnt/shared; sleep 1; umount; rmmod` or run tests/setup/reset2_tcp.sh.
- reset2_tcp.sh sometimes times out at 250s when preceded by a VM reboot (boot wait eats budget) — run reboot and reset as SEPARATE steps.
- At suite end both nodes are often EIO-wedged (LIO target) → recover with virsh destroy/start + reset2_tcp.
- Instruments live at instr=0 (per sess111): P15-INSTR (free-ag-extent-fail, xfs_alloc.c:2244), P47-INACT verdict (DISK-FREE⇒double-free | GEN-MISMATCH⇒stale-inode | DISK-LIVE-same-gen⇒lost-removal), P81-DEXT disk_claims_freed (0=in-core BMAP stale=inode bug), P82-ADD, INACT-SKIP-STALE (xfs_inode.c:2281).
