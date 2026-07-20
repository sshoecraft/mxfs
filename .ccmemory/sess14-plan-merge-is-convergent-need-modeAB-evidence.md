---
name: sess14-plan-merge-is-convergent-need-modeAB-evidence
description: sess14: 2/tcp baseline 14/16 (crash_consistency + tcp_dlm_scaling flaky). Convergent fix across sess9/12/13 = 3-way SF merge. sess9 REFUTED relax-IN_…
metadata:
  type: project
---

## sess14 STATE (build CF359E6C, criterion `./run.sh 2 tcp` 100% NOT met, marker NOT written)
- Fresh baseline on clean reboot: 14/16. Failures rotate between **crash_consistency** (1/2) and **tcp_dlm_scaling** (0/2 = MODE-A shutdown, or silent-loss = MODE-B). 5 iters of the pair alone (no reboot) = all PASS → genuinely rare/flaky; full-suite contention triggers it.
- tcp_dlm_scaling at N=2 = qnap_scale.sh workload-A: each node `mkdir n${id}_d{1..100}` into SHARED dir scale_2 → 200 entries (grows to BLOCK/LEAF, not shortform). Fail = silent dirent loss OR shutdown(MODE-A deadlock).
- crash_consistency = single-file append durability across writer virsh-destroy + survivor foreign-slice journal replay (mxfs_dlm_foreign_replay_work_fn @14080). Fail = visible<acked. DISTINCT root from dir churn.

## CONVERGENT FIX (sess9+sess12+sess13 all agree) = 3-WAY SHORTFORM MERGE
base/ours/theirs, ours-wins-per-changed-name. Needs a base snapshot of the SF dirent set captured when loaded_gen is set. Plan in [[sess13-FIX-REQUIRED-3way-sf-merge]].

## CRITICAL — DO NOT REPEAT these REFUTED fixes (sess9, build evidence):
- **Relax P9 clean-gate (drop IN_AIL skip)** = build 223CA589 → WORSE (27/30). IN_AIL skip is PROTECTIVE vs destage-race (reload mid-destage reverts own committed removal). [[sess9-root-durable-revert-and-publish-only-regression]]
- **Force slow-path when i_dlm_stale** = build 58EB95A8 → STARVATION (dlm_fairness got=7). i_dlm_stale set too frequently. 
- **di_changecount epoch discriminator** in sf_refresh → UNSOUND: per-node i_version not a shared sequence (sess13). Need ATOMIC SHARED on-disk epoch OR per-entry provenance (the merge).

## EXISTING MACHINERY to leverage: i_mxfs_ex_grant_seq + i_mxfs_dirty_seq (xfs_inode.h:139-140, sess17b Gemini epoch guard — knows if dirty state belongs to a prior EX tenure). i_dlm_dir_gen/loaded_gen (peer-modify signal, laggy/bursty). mxfs_dir_sf_refresh_if_disk_differs @6293 already FUA-reads disk SF + compares; its reload→mxfs_dlm_reload_inode has a kept_protected path (sess34) that FUA-reads cluster privately when P91 keeps the buffer.

## NEXT: tests/tcp2_characterize.sh running 3× full-suite clean-reboot → confirm whether the dominant fail is MODE-A (shutdown in dmesg: 'DLM AG lock failed'/'trans_cancel'/SHUTDOWN) or MODE-B (silent dirent loss, no shutdown). Merge fixes MODE-B only; MODE-A needs lock-ordering fix (take AG lock before trans dirties in xfs_remove, or break dir-EX<->AG-DLM ABBA). [[sess13-two-failure-modes-and-p91-falsepos-resurrection]]
