---
name: ccloop-c7ee71c6-sess293-board-complete-505-dirreuse-marginal-p296-design
description: sess293: FULL board complete on 0.11.505 (27/27 PASS 32/caw); dir_reuse 1-fail-then-pass = CHRONIC marginal pace (D-32NODE-SHARED-DIR-CREATE-PACE), N…
metadata:
  type: project
---

# sess293 — board complete on .505; dir_reuse marginal-pace finding; P296 probe design

## Board COMPLETE on 0.11.505 sv 7BFD835EDA68D87A5C6D621 (32/caw)
All 27 applicable cells PASS (open_defects red by policy, 36 open).
Sess292 had left 10 cells; this session ran them in 3 chunks.

## dir_reuse_coherency: FAIL once → PASS on immediate re-run — DIAGNOSED as chronic margin, not D-503
- Fail: 7 rounds/100s (need 8), faildist 1x32 (every node the same single pace check).
- Immediate re-run: PASS 8 rounds/58 checks in 112s.
- Phase-timeline comparison (mxfs-DRCph kmsg stamps, fail kernlog vs live dmesg):
  per-round wall ~13-15s in BOTH runs; no phase dominates; fail window had
  exh_ms≈200ms (vs 1672 in D-503) and ZERO qsrc=16 lines on test1.
- Conclusion: 32/caw dir_reuse rides the 12.5s/round threshold chronically —
  this is D-32NODE-SHARED-DIR-CREATE-PACE (major, open), and the board will
  keep flapping this cell until that defect is attacked. NOT a new ledger entry.

## dirent_publish/type_integrity ordering trap (recurring)
After any re-prep/reboot they FAIL with "no MXFS_DIRENT_WINDOW marker in this
boot" unless dirent_durability runs FIRST in the same boot. Always order:
dirent_durability → dirent_publish_integrity → dirent_type_integrity.

## D-503 P296 probe design (NOT yet written)
- Hypothesis: dir demote bast work queue-delayed behind sweep-release works on
  m_mxfs_inode_bast_wq (max_active=32, xfs_mxfs_dlm.c:13359; param 0644 but
  only read at mount-time alloc_workqueue — set before mount for A/B).
- All per-inode arms go through mxfs_bast_arm_queue (:162) and
  mxfs_bast_arm_queue_delayed (:181). Sweep queue :38645 (work body logs
  P137-PRSWEEP-ENTER/-EXIT already), publish work xfs_inode.c:2847, noino :20661.
- Work fns: mxfs_dlm_bast_work_fn :19385 (probe after ident check :19401),
  mxfs_dlm_bast_dwork_fn :19584.
- Design: u64 i_dlm_bastq_qns stamped at arm chokepoints on queued==true
  (dwork stamps now+delay so delta=excess); at work-fn entries log
  P296-BASTQLAT (capped) if excess>100ms with ino/src/S_ISDIR. Armed-count
  gauge only if decremented at cancel sites (xfs_icache.c:2353,
  xfs_super.c:1520, xfs_mxfs_dlm.c:32854) — else skip.
- Sweep chain fact: every dir demote in bast_process triggers the sweep
  (:15126 → trigger :38633, 3s ratelimit) which queues per-inode PR-demote
  works src=16 via mxfs_dlm_queue_pr_demote (:38601) on the SAME wq.
- RULE 5 consult after the measurement, before any fix.
