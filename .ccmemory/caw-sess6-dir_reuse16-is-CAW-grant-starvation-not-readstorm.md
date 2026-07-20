---
name: caw-sess6-dir_reuse16-is-CAW-grant-starvation-not-readstorm
description: sess6: dir_reuse@16 stalls round-2 (first reuse) on CAW GRANT STARVATION (stat→xfs_ilock→caw_wait_for_grant msleep on shared dir inode), distinct fro…
metadata:
  type: project
---

## sess6 — dir_reuse@16/@32 is CAW grant STARVATION, a SEPARATE root from the read-storm

### Proven (RULE 4, live stack capture on test16 during the round-2 stall)
With fua_disable=1 loaded (cache_coherency@16 PASSED 16/16 same run), dir_reuse@16 advances r1→r2 then
STALLS on round 2 (the FIRST inode-REUSE round: r1's rm-rf freed the shared dir, r2 recreates+reuses it).
`stat /mnt/shared/.dir_reuse_coherency` sits in D-state, kernel stack:
```
msleep → mxfs_pal_sleep_ms → caw_wait_for_grant+0x253 → mxfs_dlm_caw_lock →
mxfs_v5_dlm_inode_lock → mxfs_dlm_ilock_begin → xfs_ilock → mxfs_getattr_dlm_lock →
xfs_vn_getattr → vfs_statx
```
=> a node cannot get its CAW DLM grant on the SHARED reused dir inode; caw_wait_for_grant polls (msleep)
indefinitely. 16 nodes all stat/access the one shared dir in the reuse round → grant starvation (cf.
[[sess50_lessons]] "CAW WRITER STARVATION: PR readers re-grant forever, EX writer never gets a zero-PR
window"; fix was `defer_for_waiter`). NO shutdown/corruption in dmesg — it is a livelock/starvation, not
a crash. This is the PRE-EXISTING reason dir_reuse@16 never passed (the 16/17 holdout); fua_disable=1
did not cause it and does not fix it (starvation is DLM-coordination, not read I/O).

### What fua_disable=1 DID fix (keep it — build 96C5CF1F, now DEFAULT 1)
Read-storm cells: cache_coherency@4 PASS, strong_consistency@4 PASS, dir_reuse@4 PASS(!), cache_coherency@16
PASS 16/16. So fua_disable=1 is correct + necessary; it should also clear cache_coherency@32,
crash_consistency@32 (drop_caches cold reads), dlm_scaling@32 (self-recycle reads) — TEST THESE NEXT.
dir_reuse@4 passes because 4-node contention is low enough to avoid the starvation; @16/@32 hit it.

### STRATEGY (sess6 revised)
1. Confirm fua_disable=1 clears the NON-dir_reuse 32-node storm cells:
   `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="fua_disable=1" ./run.sh 32 caw cache_coherency
   crash_consistency dlm_scaling` (fresh-boot 32 first). Expect PASS (big 32/caw jump 13→16).
2. Then tackle dir_reuse@16 + @32 grant STARVATION separately (RULE 4):
   - Investigate caw_wait_for_grant (dlm/dlm_caw.c) fairness: why a node starves on the shared dir under
     N-node contention. Look at sess50 defer_for_waiter, PR-re-grant-forever, zero-PR window logic.
     Candidate: FIFO/ticket grant ordering, or bound PR re-grants when an EX/other waiter is queued.
   - The reuse angle: r2 reuses the freed dir inode; the grant contention peaks there. Possibly the
     freed+realloc'd inode's CAW slot resets and every node re-races the grant.
   - Validate at dir_reuse@8 (passes — baseline), @16 (target), keep coherency (dir_reuse verifies content).
3. dir_reuse is the LAST holdout for 16 AND 32. Everything else should fall to fua_disable=1.

### Build/infra
- build 96C5CF1F = fua_disable DEFAULT 1 (SCST-correct) + inert dir_slow_handoff_gate + probes. On disk.
- Scale script valfua_scale.sh wrapped @16 in timeout 1100 → it will KILL the stalled dir_reuse@16 and
  STOP before @32. Re-run @32 non-dir_reuse cells manually.
See [[caw-sess6-PIVOT-scst-confirmed-fua_disable-is-the-storm-fix]] [[sess50_lessons]].
</body>
