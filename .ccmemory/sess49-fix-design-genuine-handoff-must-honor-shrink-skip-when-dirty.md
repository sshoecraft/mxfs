---
name: sess49-fix-design-genuine-handoff-must-honor-shrink-skip-when-dirty
description: sess49(ccloop) FIX DESIGN: 8/tcp AG-double-free shutdown = epoch_adopt=1 genuine_handoff BYPASSES P33-DIRGROW-REVERT-SKIP → adopts stale-smaller disk…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — fix design for the 8/tcp AG-double-free shutdown

### MECHANISM (code-traced, xfs_mxfs_dlm.c mxfs_dlm_reload_inode):
- `mxfs_dir_epoch_adopt=1` (DEFAULT 1, line 5291) sets `genuine_handoff=true` when grant_epoch>valid_epoch (line 11181).
- `genuine_handoff` BYPASSES the keep-stale guards:
  - **P33-DIRGROW-REVERT-SKIP** (~11873-11894): `if (dg_inflight && !genuine_handoff)` — normally KEEPS the in-core dir fork when disk is SMALLER (size/nx shrink) than in-core because "our grow not yet destaged; disk one growth behind the leaf". Checks pin + ili_fields.
  - P43-DIR-FMTREVERT-SKIP (~11983): `if ((dfr_dirty||dfr_grant_held) && !genuine_handoff)`.
- With genuine_handoff=true, the reload PROCEEDS to xfs_idestroy_fork + xfs_inode_from_disk = destroy+rebuild the data fork from a STALE-SMALLER disk dinode (our just-grown dir block not yet durable) → SHRINKS the fork → a logical block the leaf references becomes a HOLE/DELAYSTARTBLOCK(-2) → xfs_dabuf_map !HOLE_OK (LEAFHOLE/P21H) AND xfs_free_ag_extent ltbno+ltlen>bno (AG double-free) → SHUTDOWN. (See [[sess49-8node-shutdown-is-agdoublefree-from-epochadopt-stale-reload]].)

### WHY ONLY 8 NODES: more cross-node handoff churn → more chance the epoch advances while OUR dir grow is still in-AIL/un-destaged (disk not yet a superset). 4-node PASSES.

### THE FIX (targeted, RULE 4 — prove epoch_adopt trigger first via `dir_epoch_adopt=0` test, IN FLIGHT):
genuine_handoff should adopt a CHANGED disk, but a SHRINKING disk while OUR fork is dirty/in-AIL = our un-destaged work, NOT a legit peer shrink. So: in the genuine_handoff path, STILL honor the shrink-skip (keep in-core, don't adopt) WHEN `dg_inflight` (pin || ili_fields bmap-dirty || in-AIL). Only adopt-on-shrink when our fork is CLEAN (destaged) → then disk-smaller is a genuine peer removal, safe to adopt.
- Concretely: change the P33 guard from `if (dg_inflight && !genuine_handoff)` to keep-stale whenever `dg_inflight` is true (shrink + un-destaged), regardless of genuine_handoff. genuine_handoff still allows GROW/SAME/clean-shrink adopts.
- The DEEPER root: disk SHOULD be a superset at a genuine handoff (Invariant 1 drain-before-release). The shrink proves the release-drain is INCOMPLETE for the dir grow. Forcing the drain tears the leaf (P21H, sess48). So the keep-on-shrink-when-dirty guard is the pragmatic correct behavior until release-drain completeness is solved.

### EXPECTED: epoch_adopt=0 stops shutdowns but dirent-loss returns (stale reads). The proper fix (honor shrink-skip when dirty) should stop shutdowns WHILE keeping coherency for grows. Verify: 8/tcp 24 rounds, 0 shutdown, then measure RDMISS.
</body>
</invoke>
