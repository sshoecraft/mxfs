---
name: compiled-tcp-2node-dlmfairness-slotclaim
description: 2-node TCP DLM dlm_fairness: non-CAW slot-claim fix gives unique AGs (A3E2842C); residual = rare stale-readdir self-heal.
metadata:
  type: project
tags: [compiled, tcp-dlm, dlm_fairness, disklock-slot-claim, ag-affinity, dir-coherency]
---

## 2-node TCP DLM bring-up of dlm_fairness — slot-claim root cause, fix, and residual

Central topic: getting the `dlm_fairness` criterion reliable on a **2-node TCP-transport**
cluster (test1/test2). Two distinct problems, resolved in order: (1) a hard FS-shutdown wedge
rooted in disklock slot-claim failing on the TCP path, fixed by a non-CAW verified claim; and
(2) a residual, rare, self-healing stale-readdir flake that keeps the suite from 100%.

### Build progression
- **F22321508E13160ACFD9A41** ("F22321") — baseline after the -ETIMEDOUT lost-grant retry fix;
  5/6 coherency tests reliable, dlm_fairness still flaky/wedging.
- **C44D5CF3** — added SCSI PR register/reserve to the TCP path (first slot-claim fix attempt).
- **A3E2842CCEF45CB87CF67FD** ("A3E2842C") — final non-CAW verified slot-claim; AG0 collision
  wedge eliminated.

### PROVEN ROOT of the dlm_fairness FS-shutdown wedge [[sess-tcp-ROOT-dlmfairness-both-nodes-slot0-no-scsipr]]
Symptom: dlm_fairness PASSes ~4-6× then WEDGES — iter5/6 stale-readdir (`got=1`), iters7+ hard
wedge (both nodes 0 rounds, ~6s fast-fail). dmesg showed a **real FS SHUTDOWN**: test1 `inobt
record corruption in AG 0 ... freemask 0x7fffffff80 ... xfs_difree_inobt -117`; test2
`xfs_remove → xfs_trans_cancel dirty → Corruption of in-memory data shutdown` + unrecovered
unlinked inodes = classic concurrent same-AG inode alloc/free inobt corruption.

Causal chain, proven with the `mxfs.dirwr=1` P90-PICK tracer (histogram showed `slot=0` on
BOTH nodes) and P51-INSTR SCSI sense:
1. AG affinity = `node_slot % agcount` (`xfs_dialloc_pick_ag`, `xfs/libxfs/xfs_ialloc.c`).
   Both nodes had `node_slot=0` → every inode alloc went to **AG0** → inobt freemask
   divergence → corruption.
2. `node_slot=0` on both because `mxfs: disklock: claim_slot failed: -5` (-EIO) on each TCP
   node; on failure `ctx->node_slot` stays at its 0 default (`dlm/v5_mount.c` TCP branch ~L670).
3. `claim_slot` (`dlm/disklock.c:1259`) issues SCSI COMPARE_AND_WRITE (opcode 0x89). The SCST
   LUN **rejects** it: `ret=1026 sense_key=0x5 asc=0x24 ascq=0x0` = ILLEGAL REQUEST / INVALID
   FIELD IN CDB. The target *supports* CAW (`sg_opcodes` lists `89 ... Compare and write`) but
   rejects it here.
4. Why CAW works in CAW-transport mode but not TCP: the CAW init path (`v5_mount.c` ~L731-743)
   does `mxfs_scsipr_register` + `mxfs_scsipr_reserve` (PR type 5 WRITE-EXCLUSIVE
   REGISTRANTS-ONLY) **before** claim_slot and makes claim failure fatal. The TCP path
   returned (~L722) **before** the SCSI PR block, so PR was never registered — and PR
   registration is the prerequisite SCST needs to accept COMPARE AND WRITE.

Context: sess130 had deliberately switched slot-claim from a racy plain-write to CAW because
parallel mounts collided — but CAW is dead on this target for TCP, so the switch turned a race
into a guaranteed `-EIO` → all-nodes-slot0.

### FIX [[sess-tcp-FIX-noncaw-slot-claim-unique-ags]]
First attempt (C44D5CF3): mirror the CAW path — register+reserve SCSI PR in the TCP branch
before the disklock block. This did **NOT** make CAW succeed (SCST still rejected 0x89
regardless of `caw_path 0|1` or PR registration; sense 0x5/0x24 persisted).

Final fix (A3E2842C) — new `mxfs_disklock_claim_slot_noncaw()` in `dlm/disklock.c`:
claim_slot falls back to a **verified non-CAW claim** when CAW fails: FUA-scan (`read_prio`)
for own/free slot → FUA-write our record with a unique timestamp → sleep 30ms → FUA-read-back;
accept only if `node_id` AND timestamp survived. A racing peer's later write wins the
read-back and the loser rescans — closing the sess130 race the old blind plain-write had
(harness mounts sequentially, so the common path is uncontended anyway). Defense-in-depth kept
in `v5_mount.c` TCP path: register SCSI PR + derive `node_slot = node_id % MXFS_DISKLOCK_HB_SLOTS`
fallback if claim still returns <0 (never default all nodes to slot0/AG0).

Result (dmesg-verified): test1=slot0→AG0, test2=slot1→AG1, distinct P90-PICK slots. The AG0
inobt-collision FS-shutdown wedge is **ELIMINATED**; dlm_fairness no longer dual-node shuts
down.

### Degradation characterization (pre-fix, build F22321) [[sess-tcp-dlmfairness-degrades-node2-wedge-on-churn]]
`tests/repro_pm_loop.sh 6 dlm_fairness`: iter1 PASS(13.9s), iter2 PASS(7.9s), iter3 FAIL(74.4s)
with test1 `df shared dir drained got=1` AND test2 `df node2 completed all rounds exp=50 got=6`;
iters4-6 FAIL(~7s) with test2 `got=0`, test1 PASS. node2 degrades 6/50→0/50 rounds and **stays
wedged across runs** — a SESS50-STARVE-family contamination/degradation of the dir-EX handoff,
requiring a full `tests/setup/reset2_tcp.sh` to recover. dlm_fairness = 50 rounds/node of
create+rename+rm in ONE shared dir = the heaviest dir-EX handoff churn in the suite; the 6s
lost-grant retry does not cure the wedge and may aggravate it. This was pre-slot-fix and was
largely subsumed by the AG0 root above; the hard wedge traced to the inobt corruption.

### Residual after the fix — rare self-healing stale-readdir [[sess-tcp-dlmfairness-residual-is-stale-readdir-selfheal]] [[sess-tcp-STATE-5of6-reliable-dlmfairness-residual]]
With the corruption gone, the only remaining flake is `df shared dir drained (exp=0 got=1)` at
rank1's drain-check (`tests/suite/dlm_fairness.sh` asserts `ls $D | wc -l == 0` after the df
barrier). Proven transient, not durable: standalone dlm_fairness ran 3/3 PASS (19.2/13.1/12.9s)
and post-run `ls /mnt/shared/.dlm_fairness` = 0 files on BOTH nodes — the dir is actually empty,
so `got=1` was a **stale readdir that self-heals on a later read**, not a leaked/lost dirent.
Low rate (passed full-suite run1, failed run2, 3/3 standalone).

Mechanism = the long-standing DIR-STALE-SKIP `pin=1` family: `xfs_da_read_buf`
(`xfs/libxfs/xfs_da_btree.c` ~L3153) only invalidates+re-reads a gen-stale dir DATA block when
it is NOT pinned/dirty/in-AIL; a pinned gen-stale block takes the DIR-STALE-SKIP else-branch and
is served stale to the readdir, showing a dirent a peer already removed.

Fix direction (to reach reliable 100%, not yet done): make a **readdir** (not just modifying
ops) refresh a pinned stale dir DATA block — for a non-modifying read there is nothing of ours
to lose, so force-unpin (`xfs_log_force`) + re-read, or drain+refresh on the dir-EX acquire for
the read. Hardening margin: lower `MXFS_LOCK_ACQUIRE_WAIT_MS` 6000→~2000 (50-round churn
accumulates multiple 6s lost-grant recoveries toward the barrier; won't fix a hard wedge but
tightens margins). Verify: `./run.sh 2 tcp dlm_fairness` ~10× with 0 FAIL.

### Overall state
5/6 coherency tests (cache_coherency, strong_consistency, posix_multi, mmap_coherency,
zero_silent_loss) RELIABLE; dlm_fairness = rare stale-readdir flake, criterion **NOT yet met**,
marker NOT written. All session fixes are KEEP. 8 PENDING test stubs still need porting for an
unambiguous matrix-100%: dlm_membership, scaling_curve, dlm_scaling, rsync_paired,
crash_consistency, fence_during_write, fault_netpartition, tcp_dlm_scaling
(src: `tests/cluster/test_tcp_mesh.sh` for the last).
