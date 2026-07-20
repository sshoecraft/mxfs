---
name: sess15run-UNIFYING-both-8tcp-blockers-are-tcp-dlm-acquire-starvation
description: sess15(ccloop) UNIFYING INSIGHT: BOTH 8/tcp blockers = the SAME TCP-DLM acquire starvation. dir_reuse=slow retries; tcp_dlm_scaling=acquire FAILS -11…
metadata:
  type: project
---

## sess15(ccloop) — UNIFYING ROOT: both 8/tcp blockers = TCP-DLM acquire starvation

### The single root
Under 8-way contention, the TCP-DLM inode acquire (`mxfs_dlm_lock` → `mxfs_dlm_lock_retries`, 60 × ~1s = 60s budget) STARVES on the hot shared dir (P36-RETRY ino=131) due to the sess36 master-side **queue-vs-grant race** (waiter queues while holder owns no grant → no BAST captured → stranded until its own ~1s retry re-fires the BAST). This produces BOTH 8/tcp failures:

1. **dir_reuse_coherency** — acquire RETRIES succeed eventually (correct) but cost ~60s stalls per slow round ⇒ ~630s total ⇒ RULE 0 timeout FAIL at default budget. (Passes 8/8 at TEST_TIMEOUT=900.)

2. **tcp_dlm_scaling** — acquire EXHAUSTS all 60 retries → returns **rc=-110 (ETIMEDOUT)** (PROVEN: dmesg `DLM inode lock failed: ino=... rc=-110`). The caller then proceeds to modify+commit the DIRECTORY anyway → `P58-DIRPIN-NONEX ino=537968 dlm_mode=0(NL) ex_h=1` at `xfs_inode_item_pin`/`__xfs_trans_commit` ⇒ durable dirent RESURRECTION ⇒ 1/8 PASS. The `ex_h=1 dlm_mode=NL` signature = ex_holders was incremented but the EX grant never landed (-110), yet the op committed at NL. (The P108/P-TCPEX reconcile paths at xfs_mxfs_dlm.c:10735/10781 already guard ex_holders==0, so they are NOT the source — it's the acquire-failure-then-commit path.)

### Two fix options (next session)
**A. Fix the DLM acquire starvation (fixes BOTH):** eliminate the queue-vs-grant missed-BAST so acquires succeed promptly under 8-way contention. Audit dlm/dlm.c grant paths (collect_grantee_bast_if_waiters is in upgrade@1119, fresh-grant@1238, remote@2913 — but a gap remains at 8-way; trace one stuck ino=131 acquire with DLM_TRACE). This is the highest-value fix.
**B. Defense for tcp_dlm_scaling correctness (independent, do regardless):** when the dir EX acquire returns -110, the modifying op MUST abort the transaction (trans_cancel + error) — NEVER fall through to modify+commit the dir at NL. Find the caller that ignores the -110 from `mxfs_v5_dlm_inode_lock`/`mxfs_dlm_ilock_begin` on the dir-modify path (create/rename/remove in tcp_dlm_scaling). The P58-DIRPIN-NONEX gate could be turned into an enforcement point (refuse to pin a dir at non-EX → trans abort) but that risks shutdown; prefer aborting at the acquire site.

### Verify
After a fix: `./run.sh 8 tcp tcp_dlm_scaling` → P58-DIRPIN-NONEX count = 0 AND nodes_pass=8/8; `./run.sh 8 tcp dir_reuse_coherency` P36-RETRY count drops + fits a sane budget. MUST NOT regress 2/tcp (17/17) or tcp_dlm_scaling at 2 nodes. 1/2/4 tcp currently PASS.
See [[sess15run-8tcp-TWO-blockers-tcpdlmscaling-P58-DIRPIN-NONEX-and-dirreuse-slow]] [[sess15run-FIXPLAN-8tcp-dlm-queue-vs-grant-race-and-acquire-churn]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]].
