---
name: ccloop-c7ee71c6-sess319-513-deployed-board-partial-test1-ilock-corruption-shutdown
description: sess319: .513 knob-on deployed, zsl 3/3 PASS but P34H 0 fires (fix UNVERIFIED); board batches1-2 green; NEW test1 shutdown ilock_begin corruption 306…
metadata:
  type: project
---

# sess319 — 0.11.513 deployed; new test1 in-core corruption shutdown

## Done
- make tools (sess318 clean build had wiped them; prep fails without mkfs_mxfs).
- Deployed 0.11.513 sv C774FEA614A2BB1AE74286F knob-on
  (`MXFS_EXTRA_MODARGS='icluster_dlm=1 release_proof_enforce=1' ./run.sh 32 caw prep_cluster`, 145s).
- zero_silent_loss PASS 3/3 (35s/15s/15s) — the .512 regression symptom is gone,
  BUT P34H-INCARN-POISON/-EVICT/-UNRETIRED fired 0 times on all 32 nodes:
  the retire/gate path was NEVER exercised → D-INCARN-...-512 NOT verified.
  Likely why: eviction-ring ISTALE_CAW lookup arm (xfs_inode.c:1591) handles
  common reuse; freshsrc poison needs the ring event missed (sess316 hit it
  under post-board load, hostload 22 vs 11-15 here).
- Knob-on board: batch1 7/7 PASS, batch2 5/5 PASS (incl dlm_fairness 28s —
  the tally red was capture-only). Batch3: rsync_paired PASS;
  crash_consistency + fence_during_write NO_TERMINAL_RECORD×32;
  dir_reuse_coherency FAIL = pace (rounds 6<8, 1 check ×32 — ledgered
  D-32NODE-SHARED-DIR-CREATE-PACE family).

## NEW CRITICAL (unledgered at session end; test1 left LIVE for forensics)
test1 09:09:40Z (t=1739.29, boot 08:40:41):
  XFS (dm-1): Corruption of in-memory data (0x8) at mxfs_dlm_ilock_begin
  +0x3c53 (xfs_mxfs_dlm.c:30684) → shutdown → P-WITHDRAW → P163-WITHDRAW-STAMP
  slot=0; accompanied by P71-UNDERFLOW ino=858369 mode=PR state=0 dlm_mode=0
  comm=bash (= run.sh marker probe mountpoint stat).
Prior anomalies on test1: P71-UNDERFLOW storm ino=2980 mode=EX state=1
  dlm_mode=5 comm=python3 ×9 at t=1009 (~08:57:30, during dlm_scaling which
  PASSED); P163-RECOVERY-PENDING slot=3 t=1437 (fence_during_write victim).
First failed MOUNTED probe was ~09:07 — BEFORE the 09:09:40 shutdown print,
so the damage predates it (or an earlier probe hung/failed differently).
30684 is inside/near the sess315 INODE-containment surgery region — prime
suspect window, but UNINSTRUMENTED (RULE 4 open).

## Gate-placement note (possible residual, unproven)
read_iter gate (xfs_file.c:349) runs BEFORE mxfs_read_coherency_envelope
(:362) where freshsrc poison fires → first read(2) that triggers poison may
still consume the stale bmap once before any gate sees the flag. Do NOT
patch without a repro proving it (RULE 4).

## Next
1. Read xfs_mxfs_dlm.c:30640-30700; test1 dmesg forensics; other-node P71
   sweep; then ledger the shutdown defect.
2. Re-prep knob-on only after forensics; board batches 4-6 remaining:
   fault_netpartition soak dirent_durability node_responsive kernel_health
   ag_strand_repair sustained_load dirent_publish_integrity
   dirent_type_integrity dlm_lock_correctness open_defects; then knob=0
   regression board.
