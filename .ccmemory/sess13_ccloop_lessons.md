---
name: sess13_ccloop_lessons
description: sess13 (ccloop 4eef1f39 s13) — test_unlink_visibility ROOT REFRAMED+PARTLY FIXED: shortform-PARENT-dir new child invisible to peers (ENOENT), not blo…
metadata:
  type: project
---

## sess13 (ccloop 4eef1f39 s13) — build 6B8A19F5 (deployed all 4 nodes)

### ROOT CAUSE REFRAMED (RULE 4, fully proven) — sess120 was WRONG about the mechanism
test_unlink_visibility's failure is NOT a block-format dir-data lost-update. It is a
**SHORTFORM PARENT-DIR new-child invisibility**: a node `mkdir`s a child dir (uv_diag, ino 132)
under a SHORTFORM parent (.mxfs_test, ino 131). The new dirent lives INLINE in 131's dinode
(shortform fork). xfs_create's publish-before-notify (`mxfs_dlm_dir_durable_signal` →
`mxfs_dir_flush_data_blocks`) flushes only DATA-fork blocks — a shortform dir HAS none, so it
does only a log_force (durable in LOG, not in the home cluster). Under CAW a peer's cold read of
131's inode cluster does NOT BAST the owner, so the new dirent isn't destaged until the next async
xfsaild iflush. Peers resolve .mxfs_test(131) fine but get **ENOENT on uv_diag** → EVERY peer
create under it fails "No such file or directory". The "files lost" were NEVER CREATED (peers got
ENOENT); not a lost update.

### PROOF (decisive experiments, tests/diag_uv.sh — KEEP)
- WARM and COLD (drop_caches) reads on ALL peers showed only node1's 30 (sess120's "disk has 120"
  came from a create-only+sleep2 variant that masks the race).
- Peers have ZERO P-CRNAME on pino=132 → their creates never reached xfs_create.
- Captured create errors: all peers create_errs=30/30 "No such file or directory"; component
  probe = mnt(128)✓ .mxfs_test(131)✓ **uv_diag=ENOENT**.
- DECISIVE: `DROP_ON=creator` (drop_caches on test1 after mkdir, before storm) → ALL peer creates
  succeed (0 errors). Proves test1-side durability of the shortform parent cluster.

### FIX (build 6B8A19F5) — proactive shortform-parent cluster flush, gated to mkdir
New `mxfs_dlm_dir_inode_durable(dp)` (xfs_mxfs_dlm.c ~482; proto in .h; reuses sess85
`mxfs_inode_cluster_durable`: log_force→imap_to_bp→iflush_cluster→bwrite→blkdev_flush). Shortform
dirs + multi-node only. Called from xfs_create AFTER `xfs_iunlock(dp)` (MUST be ILOCK-free —
xfs_iflush_cluster skips inodes it can't ilock_nowait(SHARED); confirmed xfs_inode.c:4027).
**GATED to `S_ISDIR(du.ip)` (mkdir only)**: the UNGATED v (build F260DFCC, flush on every create)
caused per-create log_force(SYNC) storms → CAW EX starvation → rc=-110 ETIMEDOUT force-shutdown
(SHUTDOWN_CORRUPT_INCORE at xfs_mxfs_dlm.c:~4182). File-create visibility already works without
the flush (cross_visibility passes at baseline).

### STATUS — partial, NOT done
- repro_blockdir_visib.sh: creates now succeed, 120/120 visible, 0 rm-fail, 0 shutdowns. Fix WORKS.
- Criterion runs are UNSTABLE/SLOW (rename_visibility 250s vs healthy 1.4s; a node force-shuts-down
  mid-run; different subtest fails each run). This is CAW STARVATION (SESS50-STARVE), worsened by
  the heavy flush. UNGATED run got unlink past creates → "26 files remain" (delete-side, was masked).
- MUST hard-reboot (virsh destroy+start ALL 4, LIBVIRT_DEFAULT_URI=qemu:///system) IMMEDIATELY
  before the criterion, NOTHING run in between (reproducer contaminates → slowness).
- cc_run4.log is a clean-reboot run kicked off at relay boundary — next session: read it first.

### NEXT (next session)
1. Read /tmp/cc_run4.log result (clean-reboot run).
2. If still slow/unstable: the gated flush may STILL be too heavy, or it's pre-existing SESS50
   starvation. Consider making the flush lighter (skip blkdev_issue_flush? or async) OR addressing
   CAW writer starvation (sess50 defer_for_waiter). Watch for rc=-110 ETIMEDOUT in dmesg.
3. The delete-side "26 remain" (block-dir unlink lost-update) is the NEXT layer once creates+slowness
   are solid. RULE 5: consider Gemini — this is the deep concurrent-mkdir/shortform class
   (sess106/107/119/120 lineage). diag_uv.sh DROP_ON={creator,peers,all} is the key prover tool.
