---
name: sess78-scst-caw-abort-reclaim-fix-and-p78-torn-format-barrier
description: sess78: SCST CAW abort-reclaim fix (separate /src/scst repo, branch caw-abort-reclaim) fixes D-state wedge cascade; + MXFS P78 format/literal torn-di…
metadata:
  type: project
---

## sess78 (run 14d31183) — two parallel fixes in flight

### A. SCST target fix (done by a SEPARATE Claude Code session, repo /src/scst — NOT this MXFS tree)
The user's SCST session root-caused + fixed the recurring SCST host wedge that has
contaminated many 16-node MXFS runs (sess14/47/52/77/93 D-state `iscsi_conn_cleanup`
threads pinning conn refcounts → permanent device wedge → manual host reset needed).

- **Repo/branch**: fork https://github.com/sshoecraft/scst, branch `caw-abort-reclaim`,
  commit 488704520. Local master fast-forwarded e2c57de2d→upstream 83745c0a2 (8 commits,
  none touched blocking/atomic/abort path).
- **Fix file**: `scst/src/scst_targ.c`
  - new `__scst_check_unblock_aborted_scsi_atomic_cmd()`: an aborted cmd parked on
    `dev_exec_cmd_list` with `scsi_atomic_blockers>0` is detached from every blocker's
    `scsi_atomic_blocked_cmds[]` (preserving non-NULL⇔count>0 invariant, freeing the array
    when empty to avoid UAF) and re-activated.
  - `__scst_unblock_aborted_cmds()`: added a `dev_exec_cmd_list` reclaim walk in the same
    dev_lock/IRQ-disabled region as the existing blocked_cmd_list walk, same tgt/sess filter.
  - Closes the orphan window: aborted atomic-blocked cmd whose blocker never completes
    (mass-NEXUS_LOSS under CAW storm) gets reclaimed instead of pinning conn refcount forever.
  - **Doc correction** (docs/caw-abort-reclaim-fix.md): CAW is SCSI_ATOMIC not serialized;
    the CAW↔READ cycle is impossible by construction.
- **Version marker**: `modinfo -F version scst.ko` → `3.11.0-pre+caw-abort-reclaim.1`.
- **To deploy/test** (per user): `cd /src/scst/scst && make` (already built clean there),
  install to /lib/modules/$(uname -r)/extra/scst.ko, reload scst (needs current wedge cleared
  first), confirm version marker, then run the criteria. Reloading scst tears down the iSCSI
  target → must unmount mxfs on all nodes + iSCSI logout first. RULE 2: reloading scst module
  is NOT a host reboot — allowed. Fold into the mandatory clean cluster reset for a real run.

### B. MXFS P78 format/literal-area torn-dinode barrier (THIS tree, build 7D1492FC)
Targets posix_semantics_multi16 >600s ROOT (sess77 PROVEN: durable on-disk dir-inode with
di_format=EXTENTS but literal area still holding shortform dir bytes "node7..").
- **Mechanism found**: `xfs_inode_to_disk` (xfs/libxfs/xfs_inode_buf.c:445) writes di_format
  UNCONDITIONALLY from in-core if_format; `xfs_iflush_fork` (xfs/libxfs/xfs_inode_fork.c:587)
  only REWRITES the dinode literal area when the matching data-fork flag (DEXT/DBROOT/DDATA)
  is in `ili_fields`. A flush carrying CORE-but-not-DEXT after a LOCAL→EXTENTS conversion
  publishes di_format=EXTENTS over stale shortform literal bytes = the torn dinode.
- **Fix** (xfs/xfs_inode.c, in xfs_iflush right before the sess62 bmbt-durable block /
  xfs_inode_to_disk): for multi-node DIR, !need_iread, non-empty fork — FORCE the matching
  data-fork bit into ili_fields so the literal area is rewritten to MATCH di_format. Detector
  `P78-FMT-TORN-FIX` logs ino/newfmt/ondisk_fmt/ili_fields/forcing (≤400×). Placed AFTER the
  sess119 EX discriminator + P17B epoch guard → only runs on authoritative current-tenure
  flushes. Idempotent when fork already coherent.
- **NOT yet deployed/verified**. NEXT: clean virsh destroy+start ALL 16 + reset, deploy
  7D1492FC, run posix_semantics_multi16, grep `P78-FMT-TORN-FIX` (confirms H1 fired) + confirm
  <600s / 0 shutdowns. Then rsync_paired (148%) + tcp_dlm_scaling (pending).

Marker NOT written. Related: [[sess77-posix-multi16-durable-dir-format-content-corruption]]
[[sess74-readdir-ilock-self-deadlock-and-torn-dinode-barrier]] [[sess47-scst-wedge-pr-recovery-procedure]]
[[sess14-scst-wedge-host-reboot]]
