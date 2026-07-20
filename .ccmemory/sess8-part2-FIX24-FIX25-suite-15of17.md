---
name: sess8-part2-FIX24-FIX25-suite-15of17
description: sess8 part2: 8/tcp suite 15/17 ×2 (run109/110, build 38D787B1). FIX-24 demote-wait 3s poll (dir_reuse in-suite PASS). FIX-25 ioend EX admit (3-task w…
metadata:
  type: project
---

# sess8 part 2 — FIX-24/25, harness guards, suite at 15/17

Builds: B2787BC7 (FIX-21/22) → D71F29A6 (FIX-23 — REGRESSED, reverted) → FCCC9419 (revert + soak dump_stack gating) → 1C7B7752 (FIX-24) → **38D787B1 (FIX-25, runs 109/110)**.

## Suite trajectory (8/tcp full, clean cycle each)
- run104 (B2787BC7): 12/17 — dir_reuse timeout POISONED fence/fault/soak/tds (leftover processes survive local `timeout` kill!).
- run106 (+cascade guard in run.sh): 15/17 — fails: dir_reuse (pace), soak (dmesg "Call Trace" hits from OUR OWN ungated dump_stacks in P-DIRSTALE + P1-AGWAIT).
- run107 (FIX-23): 11/17 REGRESSION → reverted. FIX-23 (gen-0 release on every -ETIMEDOUT retry) kills LIVE grants in the re-affirm case (FS holds cached EX, re-request times out → release removes own GRANTED master entry → double-EX). Receiver-side GRANT-REJECT-UNSOLICITED (dlm.c ~3910) already covers the no-mirror discard.
- run109 (FIX-24): dir_reuse in-suite PASS 8/8 (first!); fence 0/8 = test6 wedged in the FIX-25 deadlock (below); tds inherited.
- run110 (FIX-25): **15/17** — everything PASS except dlm_scaling 7/8 (test6 got=0: `.dlm_scaling/node6/f1: No such file or directory` = peer-created-dir VISIBILITY race at setup) and tcp_dlm_scaling 2/8 (pace "within window" + `drained exp=0 got=2` residual ghosts + "barrier churn" on test5).

## FIX-24 (PROVEN run106 → run109/110): demote-wait rescue poll 30s→3s
- run106 dir_reuse r10: test6's awk slept the FULL 30s in the ilock demote-wait (P73-WAITSTALL ino=10488255 state=2 ex=1 bast_pend=0 work_busy=0 — zombie), rescue arms then repaired instantly. That single sleep = a 28s create-phase straggler; the per-round barrier propagates it to everyone (five/run ≈ the whole 480s budget overshoot). Round pace analysis technique: mxfs-DRCph r=N per-node timestamps; the "33s verify" was really ONE node's late create-done + barrier.
- Fix: wait_event_timeout 30*HZ → 3*HZ in mxfs_dlm_ilock_begin's demote-wait; P73 print every 10th timeout (cadence preserved). Arms are state-gated no-ops on live drains.

## FIX-25 (LIVE-STACK PROVEN run109 test6): ioend vs BAST-drain 3-task deadlock
- Cycle: bast_process → filemap_write_and_wait → folio_wait_writeback ⟵ folio ends only when xfs_end_ioend converts unwritten extent → xfs_trans_alloc_inode → xfs_ilock(EX) → mxfs demote-wait (state BAST/DEMOTING) ⟵ blocked by that same bast. test6 wedged 150s+ (P73 mode=3(PR!) work_busy=3), fence 0/8 barriers.
- Fix: `xfs_task_in_ioend()` (pal/linux/xfs_aops.c, current_work()->func == xfs_end_io; decl in xfs/xfs_aops.h) + `mxfs_ilock_admit_ioend()` (xfs_mxfs_dlm.c, before mxfs_dlm_ilock_begin): admit nested EX when state BAST/DEMOTING && mirror g2==EX. Pre-loop + in-loop arms. P15-REL-ABORT machinery re-arms the release after. P25-IOEND-ADMIT print (0 fires run110 — rare safety net).
- The mode=PR-with-pending-conversion wedge cannot form anymore (EX drains complete conversions first).

## Harness (run.sh) cascade guards (sess8)
- On any node no-result: pkill -f script THEN `fuser -k -m $MNT` on ALL nodes (run108: a surviving `rm -rf` CHILD died on AG acquire rc=-110 → error-path shutdown → poisoned 3 later tests on test7).
- saw_noresult tracking + "(killed leftover ...)" log line.

## Soak dmesg-clean fix
- P-DIRSTALE (pal/linux/xfs_buf.c ~121) and P1-AGWAIT (xfs_mxfs_dlm.c ~21020) dump_stack()s now instr-gated — their "Call Trace" keyword failed soak's DPAT scan during NORMAL block→sf shrink binvals. pr_warn lines stay.

## OPEN (the last two, run110 shapes)
1. dlm_scaling 1-node setup race: peer-created parent dir not yet visible → own mkdir -p fails silently → 0 ops. (Also seen run107 as P26-IGET-FAIL .dlm_scaling err=-2 on test3.) New-dir cross-node visibility latency class.
2. tcp_dlm_scaling: 150-round fairness-style churn — "within window" pace fails on ~4 nodes + drained got=2 (residual SF ghost beyond FIX-22 — check P22-SFRB fires + which arm resurrects at 150-round scale) + test5 "barrier churn".
3. sess7 liveness gap still open: fs-shutdown node keeps DLM grants (zombie wedges cluster).

## Procedures
- Full suite ~35min: cycle → NFS mount all → `nohup ./run.sh 8 tcp > runNNN.log` → poll pgrep 10s.
- Failed-test node logs preserved at /tmp/run_<test>_<RUNID>/ (test1..test8 files).
- dmesg harvest BEFORE cycling (per-run dmesgNNN_tK.txt in scratchpad).
- criteria.json: jq per-test .runs["8/tcp"]. 1/2/4-node still unmeasured this generation.
