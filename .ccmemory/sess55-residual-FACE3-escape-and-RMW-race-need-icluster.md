---
name: sess55-residual-FACE3-escape-and-RMW-race-need-icluster
description: sess55 residual after 4 fixes (build 2C60CCE9): tcp_dlm_scaling/dlm_fairness still leak ~1/run via FACE3-escape (drain gives up) + cross-node RMW rac…
metadata:
  type: project
---

## sess55 residual — build 2C60CCE9 (4 fixes KEEP, see [[sess55-FIX-tcp_dlm_scaling-three-faces-coresident-cluster]]) is NOT yet reliable 17/17. Runs: d3✓d4✓(43A254CF) d5✗ d6✗ d7✓d8✓(2C60CCE9) d9✗ d10✗ d11✗. ~50% pass.

### THE 4 FIXES WORK but don't fully close it. Remaining failure modes (all rare, nondeterministic, hard-contention regime):

**1. FACE 3 ESCAPE (the main residual, ~1/run on tcp_dlm_scaling OR dlm_fairness — same workload):** My FACE3 drain self-skip retry (P55D, mxfs_inode_cluster_durable rc==0 path) is LOAD-BEARING (P55D fired 10x/run on node1) but the 25-iteration retry budget isn't always enough. Under shared-dir churn, ip's ILOCK is held by a concurrent op for >50ms, the release drain GIVES UP (P9-ICD-FAIL), ip released to NL still in_ail -> a later co-resident cluster flush hits ip at NL (P119-NONEX i_dlm_mode=0 in_ail=1) and DISCARDS the committed removal -> leak (d11: got=1 n2_r132, node2 P119=1 i_dlm_mode=0=1). d9 leaked with P119=0 (a no-marker variant = genuine cross-node RMW race, GPT: "merge overlay reduces but does NOT close the cross-node RMW race").

**2. d10 ROOT-DEADLOCK (rare one-off, did NOT reproduce in d11):** node2 EFSCORRUPTED shutdown at mxfs_dlm_ilock_begin:9741, ino=128(ROOT) mode=3(PR) rc=-110 ETIMEDOUT after dur_ms=184492 (184s!). node1 had a STUCK pr=1 holder on root 128 (P36-MHT-REARM "busy ex/pr/pin in-flight" repeating); node1's hung mkdir was in xfs_lookup->mxfs_dlm_dir_consumer_refresh->xfs_ilock->mxfs_dlm_ilock_begin. A pr_holders LEAK on root (my create-pin uses ex_holders not pr, so likely pre-existing/consumer_refresh path). Watch for recurrence.

### GPT-5.5 RULE-5 design (on file) — the COMPLETE fix is **ICLUSTER DLM lock** (per-4KB-inode-cluster EX: acquire, blkdev_flush, FUA-read fresh, overlay only authoritative inodes, write, flush-if-release, release). Closes the cross-node RMW race AND lets durability be cheap (no per-inode trylock-skip races) so release needn't starve. GPT ranked: (1) mandatory durable-drain-before-EX→NL/PR demote + ICLUSTER lock; (2) minimal: don't accept EAGAIN/drain_ms=0 as durable while in_ail + the FACE2 create-pin (done) + FACE1 PR exception (done); (5) BACKSTOP: P119-at-NL for LIVE same-incarnation in_ail = SKIP not DISCARD (do not copy, do not mark clean, do not remove from AIL, clear IFLUSHING, wake waiters, return 0, queue worker) — but the wedge-prone "leave dirty" must be done carefully (detach ip from bp->b_li_list so xfs_iflush_done doesn't remove it from AIL = loss).

### NEXT SESSION PLAN:
1. Implement GPT backstop #5 (P119-at-NL skip-not-discard) carefully — guarantees no loss when the drain fails. Study xfs_iflush flush_out + xfs_iflush_cluster li_list accounting first.
2. If still leaking (RMW race), implement the ICLUSTER DLM lock (GPT #1) — the real fix. Needs a new DLM resource keyed by (agno, cluster_agbno); deadlock order: per-inode DLM > ILOCK > ICLUSTER > buffer; trylock co-residents only.
3. dir_reuse_coherency still ~285s (sess34 6s-handoff) = RULE-0 perf, after reliability.
Repro: reboot test1/test2; PLAIN=1 NOREBOOT=1 bash tests/tcp/fg_one_run.sh dN. Per-test fail logs preserved at /tmp/run_<test>_<RUN_ID>/. dmesg at /tmp/fg_dN_node{1,2}.dmesg.
