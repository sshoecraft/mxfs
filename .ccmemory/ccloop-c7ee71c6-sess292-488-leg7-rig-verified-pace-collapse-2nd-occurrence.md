---
name: ccloop-c7ee71c6-sess292-488-leg7-rig-verified-pace-collapse-2nd-occurrence
description: sess292: D-488 leg7 1a+1b RIG-VERIFIED on 0.11.505 (ag_strand_repair 32/32, P294 Enew&gt;Eold chain clean fleet-wide); pace-collapse-503 2nd occurren…
metadata:
  type: project
---

# sess292 — leg-7 rig verification + pace-collapse second occurrence

## D-488 leg 7 (sess290 1a + sess291 1b) RIG-VERIFIED on 0.11.505 sv 7BFD835EDA68D87A5C6D621
- Prep note: sess291's `make clean` deleted tools/ binaries; prep_cluster FAILED on missing mkfs_mxfs. `make tools` then `./run.sh 32 caw prep_cluster` (73s OK). Always rebuild tools after make clean.
- ag_strand_repair PASS 32/32 (strands=1 repaired=2 declined=0 abandoned=0 faults=0, 79s/240s).
- Verified chain (test1): P200-STRAND-INJECT ag=0 → P5N disk_held=1 repair=1 → worker P294-READOPT-MINT type=3 ag=0 Eold=1 Enew=2 → P295-RX-READOPT-MINTED gep=2 → P12-WORK COMMIT demoting (normal drain release) → normal re-acquire cycles. No Eold republish.
- Fleet sweep all 32 nodes: MINT=1 each, P295-FAIL=0, P295-GONE=0, P243-AGAUTH-UNBOUND=0, P294-REAFFIRM-MISMATCH=0, faults=0.
- The P5N line prints `repair=` from the readopt flag, so ag_strand_repair.sh's `disk_held=1 repair=1` grep stays compatible.
- Board on .505 PASS so far: precond dlm_fairness dlm_membership dlm_scaling scaling_curve rsync_paired sustained_load fio_perf fio_perf_vs_xfs cache_coherency strong_consistency mmap_coherency posix_multi zero_silent_loss fence_during_write crash_consistency(2nd run) ag_strand_repair. Remaining: dir_reuse_coherency fault_netpartition soak dlm_lock_correctness dirent_durability dirent_publish_integrity dirent_type_integrity node_responsive kernel_health open_defects.

## D-POSTLOAD-SYNCWRITE-PACE-COLLAPSE-503 — SECOND occurrence (chunk D: posix_multi, zsl, then crash_consistency FAIL 0/32 NO_TERMINAL_RECORD)
Evidence, test17 fail window 13474–13566 vs PASS control window 13888+ (same node, minutes later):
- THE STALL = shared-dir EX acquire latency: dd P36-MHT-REARM ino=5250372 (the shared .crash_consistency dir) exh_ms=1672, strikes 114+ re-arming @6ms; datawrite phase 52s for 50 ops (~1s/op ≈ dir handoff cadence).
- REFUTED: serial console printk stall — console_loglevel=1 (printk "1 4 1 1"), pr_warn never reaches ttyS0. 12,600 dmesg lines/92s is ring-only, negligible.
- REFUTED as sole cause: qsrc=16 (dir_ex_sweep) release torrent — PASS window had the SAME torrent (315 qsrc=16 + 716 P70-BP ENTRY per 40s vs fail's 313+369 per 90s) and still passed in 20s.
- Discriminators fail vs pass: P50-RD dd dir-block re-reads 3463 vs 500; P12-AGBAST-RX 100 vs 10 per 40s. Per-create trace: PW-ADOPT dir nx3→4, 3× P50-RD fresh dir-block reads, P198-RELOAD-DEMOTE-WAITED 3ms — all cheap; the 1.7s is WAITING for the EX.
- zsl→crash_consistency back-to-back does NOT repro (PASS 20s). Both real occurrences had ~10-13 accumulated cells first.
- OPEN hypothesis: dir demote/handoff work queued behind sweep-release works on m_mxfs_inode_bast_wq (UNBOUND, max_active=mxfs_bast_wq_max_active — check default; sess3 26c41354 considered cap 16). Next: measure queue→run latency for the dir's demote work; RULE 5 consult with bundle.
- Mechanics: sweep = mxfs_dlm_pr_sweep_trigger (3s/node ratelimit) walks whole s_inodes (cap 1M), queues qsrc=16 demote for every idle cached PR reg file. crash_consistency = 32 nodes × 50 O_SYNC dd into ONE shared dir.
