---
name: sess14-PROVEN-writeside-shortform-resurrection-n2r6-stuck
description: sess14 PROVEN (dirwr capture): 2/tcp churn-flake = WRITE-side shortform stale-base resurrection. A removed dirent (n2_r6) gets durably stuck on BOTH…
metadata:
  type: project
---

## DECISIVE CAPTURE (build CF359E6C, dirwr=1, tests/cc_df_capture.sh, full-suite repro)
Run failed dlm_fairness(1/2) + tcp_dlm_scaling(1/2). dmesg detectors on shared shortform dir ino=17313886:
- BOTH nodes show `n2_r6` PERMANENTLY in the dir base. test2: `P-SFDIR-FASTEX count=1 names=[n2_r6] size=19` repeated; `P62-RELOAD-FORK-SHRINK incore_size=19 disk_size=19 in_ail=0 pin=0`. test1: `P-SFDIR-FASTEX names=[n2_r6 n1_rXX...]` — n2_r6 always in test1's base as it churns n1_rXX.
- n2_r6 = node2's round-6 entry (dlm_fairness: create n2_r6 → mv n2_r6.done → rm). It was REMOVED but is durably STUCK on disk (disk=19=[n2_r6] on both nodes) = RESURRECTION (the `df shared dir drained got=1` leftover; also the tcp_dlm_scaling silent-loss / cc count families).

## MECHANISM (write-side, RULE-4): a node RMWs a STALE shortform base that still contains n2_r6 (it didn't reload the peer's durable rm before its own RMW) and writes [.., n2_r6, ..] back to disk → resurrects. Once durable on disk, NO read-side fix helps (both nodes correctly read the stuck disk image). Must prevent the durable write. Earlier crash_consistency capture: failing READER (test1) showed NO write-side detectors → that face is read-side staleness, but the dlm_fairness/tcp_dlm_scaling face is write-side.

## WHY simple fixes fail (sess9, do NOT repeat): relax-IN_AIL-gate → reverts own rm on destage race (27/30); force-slow-path-on-stale → starvation. adopt-disk-when-clean doesn't help (disk is durably stuck). [[sess9-root-durable-revert-and-publish-only-regression]]

## FIX = 3-WAY SHORTFORM MERGE (sess13 convergent plan, evidence now confirms). base/ours/theirs per name across (base∪ours∪theirs): if we changed it (ours!=base) take OURS, else take THEIRS(disk). Robust to destage race: our delta (base-vs-ours) protects our rm from a stale disk; peer delta adopted only for names we didn't touch (peer's rm is durable pre-acquire via Invariant-1). base = snapshot of SF image at last coherent (re)load. Implement in mxfs_dir_sf_refresh_if_disk_differs (xfs_mxfs_dlm.c:6293) + new i_dlm_dir_sf_base field. [[sess13-FIX-REQUIRED-3way-sf-merge]] [[sess14-plan-merge-is-convergent-need-modeAB-evidence]]

## HARNESSES (RULE 3, in-tree): tests/cc_df_capture.sh (full-suite + dirwr detector capture on churn-fail), tests/cc_dirvis_probe.sh, tests/tcp2_characterize.sh. crash_consistency.sh + dlm has A/B discriminator (mxfs-cc-DISCRIM cnt0/pureLUN/direx). Repro = full ./run.sh 2 tcp (~6min, ~1 churn-fail/run, rotates {crash_consistency,dlm_fairness,tcp_dlm_scaling}).
