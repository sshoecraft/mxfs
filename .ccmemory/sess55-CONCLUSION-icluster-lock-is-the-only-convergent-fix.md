---
name: sess55-CONCLUSION-icluster-lock-is-the-only-convergent-fix
description: sess55 CONCLUSION: piecemeal in_ail fixes CANNOT close tcp_dlm_scaling — the faces interlock (skip↔reload-revert↔discard). GPT's ICLUSTER DLM lock is…
metadata:
  type: project
---

## sess55 FINAL CONCLUSION — keep build 2C60CCE9 (4 fixes, net progress: pre-session 99A4E4905 was 14/17 with dir_reuse readdir=0; now ~50% full-suite pass, dir_reuse fixed). Criterion (reliable 2/tcp 17/17) NOT met. See [[sess55-FIX-tcp_dlm_scaling-three-faces-coresident-cluster]] (the 4 fixes) and [[sess55-residual-FACE3-escape-and-RMW-race-need-icluster]] (residual).

## WHY PIECEMEAL in_ail FIXES CANNOT CONVERGE (proven this session):
The shortform shared dir D's committed change (a removal) must survive THREE in-core-vs-disk reconciliation points, ALL of which currently prefer stale disk for a non-EX inode:
1. **xfs_iflush P119** (discards non-EX dirty) — fixed for PR (P55), escapes at NL.
2. **mxfs_iflush_cluster_merge_dirs** (overlays disk on non-flushing slots) — fixed for PR (merge-keep), overlays at NL.
3. **P34D-RELOAD-FRESHSRC** (reacquire adopts FUA-fresh disk over in-core) — NOT fixed; reverts the change on the node's NEXT EX-acquire.
Even if I make P119+merge SKIP-not-discard at NL (preserve in-core), the node's next op RE-ACQUIRES EX and P34D ADOPTS stale disk → reverts the preserved change anyway. Fixing P34D needs a 3-way merge (base/ours/theirs) because "in-core has FEWER entries than disk" is AMBIGUOUS: it can mean "we removed an entry" (keep in-core) OR "peer added an entry, we're stale" (adopt disk) — count/in_ail alone can't disambiguate. The 3-way SF merge (P-SFMERGE) exists but is historically unstable (resurrects). So the faces interlock; no single in_ail guard closes it.

## THE CONVERGENT FIX = GPT-5.5's ICLUSTER DLM LOCK (RULE-5 design on file, [[sess54-gpt-coresident-cluster-flush-design]] + sess55 GPT consult):
A new DLM resource per 4KB inode cluster. For EVERY full-cluster write on a shared mount: acquire ICLUSTER EX → blkdev_issue_flush (destage peer writes) → FUA-read fresh 4KB → overlay ONLY inodes this node is authoritative for (EX, or RELFLUSH-current-tenure, or PR+in_ail+same-incarnation) → write 4KB → blkdev_flush if release → release ICLUSTER. This makes the on-disk cluster ALWAYS coherent (serialized + fresh-RMW), so:
- The cross-node RMW race (d9 no-marker leak) closes.
- P34D adopt-disk becomes CORRECT (disk has everything) → no reload-revert → no 3-way merge needed.
- Durability-before-release is cheap (no per-inode trylock-skip race) → FACE3 escape closes.
Key for impl: DLM key = (agno, cluster_agbno) or cluster fsb. Deadlock order: per-inode DLM > ILOCK > ICLUSTER > buffer. Co-resident inodes: trylock ONLY (never block on a co-resident ILOCK while holding ICLUSTER). BAST callback queues a worker (no inline heavy work). Acquire ICLUSTER only on multi-node mounts. Within 2x-native perf: it serializes only same-4KB-cluster writers (the real physical conflict domain), and the hot dir is already serialized by its own inode DLM lock.

## NEXT SESSION: implement the ICLUSTER lock. Study mxfs_v5_dlm_inode_lock / mxfs_ag_dlm_lock (xfs_mxfs_dlm.c + dlm/) for the resource-naming/acquire infra to add a cluster resource. Wire the cluster-write paths: mxfs_inode_cluster_durable (xfs_mxfs_dlm.c ~1684), the bast_process release flush loop (~5570), and xfsaild's xfs_iflush_cluster→bwrite (xfs_inode.c ~5733 bwrite site) + pal/linux/xfs_buf.c mxfs_submit_partial_inode_write (~1949). Repro: reboot test1/test2; PLAIN=1 NOREBOOT=1 bash tests/tcp/fg_one_run.sh dN (~545s). The residual leak is tcp_dlm_scaling OR dlm_fairness (same workload) ~1/run; also watch the rare d10 root(128) pr_holders-leak deadlock (mxfs_dlm_dir_consumer_refresh lookup path).
