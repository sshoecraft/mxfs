---
name: sess6-ccloop-8node-dirreuse-inode-reuse-cascade-faces
description: sess6(run6614): 8-node dir_reuse flaky (~1/3) — faces: imap_to_bp failed rc=-5 (stale inode imap after free/realloc), torn extent-map (detected/preve…
metadata:
  type: project
---

## sess6 (run 6614) — 8-node dir_reuse residual faces (build 9AA569A0, clean disks)

### CRITERION STATUS: 1/tcp, 2/tcp, 4/tcp = 100%. 8/tcp = 16/17 — SOLE blocker = dir_reuse_coherency.
8-node dir_reuse reliability ~1/3 (run1 PASS, run2 FAIL, run3 FAIL in drc_reliability 8). Genuinely flaky at 8-node contention (NOT disk-space — that's fixed, rsyslog masked).

### 8-NODE dir_reuse FACES (drc_reliability 8, clean disks):
1. **`mxfs: DLM inode reload imap_to_bp failed: ino=<fileino> rc=-5`** (test3/test4, run3) — the inode reload can't map a FILE inode (one of the dir's data files) to its cluster buffer (rc=-5 EIO). = stale inode imap after the rm-rf freed the inode cluster and recreate reallocated it; a peer's inobt/imap view is stale → wrong cluster location. This is the **inode-reuse cascade** (sess3 memory). Distinct coherence domain from dir-block: it's AG INODE ALLOCATION (inobt/finobt) + inode-cluster coherence across the rm-rf+recreate churn.
2. **P-IFLUSH-GAP-DETECT ino=131** (test1) torn extent map (divergent grow) — DETECTED and prevented (no shutdown; sess49b TORN-DISK gate + iflush-gap detector work). Not the failing face here.
3. **small dirent undercount** (run2: readdir=793/800, 7 lost, no shutdown) — the fine residual leaf/data stale-base loss, rarer but present at 8-node.

### NEXT (RULE 4): fix 8-node dir_reuse. Two sub-problems:
a) **imap_to_bp rc=-5 inode-reuse cascade** (likely highest-leverage shutdown/reload face): find `mxfs: DLM inode reload imap_to_bp failed` in xfs_mxfs_dlm.c (mxfs_dlm_reload_inode). A reload of a FILE inode whose cluster was freed/realloc'd by a peer gets a stale imap. Need inobt/inode-cluster coherence: on reload, if imap_to_bp fails, the in-core inode/imap must be re-derived from a FRESH inobt (evict cached AGI/inobt/inode-cluster buffers on the AG). Check the AG-meta coherence (pag_dlm) covers inobt on the free/realloc handoff. Compare to the dir-block gg_refresh approach: the inode-alloc side may need an analogous grant_gen-triggered inobt/AGI refresh.
b) small dirent undercount — the fine leaf/data tail; may shrink once (a) is fixed (fewer stale reloads).

### FAST repro: `scripts/drc_reliability.sh 8 6` (each 8-node run ~7-9min; clean /root/drc_*.dmesg between — 16MB dumps fill test5-8's small 6.1G disks). ENSURE rsyslog stays masked on all 8 (esp. test5-8) or disks refill and mask everything (see [[sess6-ccloop-8tcp-16of17-diskspace-was-masking]]).
See [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]] [[sess3-ccloop-STATE-keepmiddle-fixes-dir_reuse-remaining-is-inode-reuse-cascade]]</body>
