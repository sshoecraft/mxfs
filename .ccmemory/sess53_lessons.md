---
name: sess53_lessons
description: "sess53 — cross_visibility failure is a SHORTFORM-DIR inode-reload coherency miss, NOT bnobt double-alloc (8-session red herring). Reload-not-firing on reader."
metadata: 
  node_type: memory
  type: project
  originSessionId: af35ad34-ffb3-4496-9a06-12a68b06dc4e
---

# sess53 (2026-06-03) — MAJOR REFRAME of the cache_coherency root

Build `C2D30DB0A37A12264B76A35` (= sess52 BDC9BB93 + P88 now also logs dirty/in_ail/pin/delwri;
pure diagnostic, KEEP). Deployed all test1-4 via reset4.sh 4.

## What I proved (RULE 4, direct measurement)

1. **The bnobt/P88 hunt (sess44-52) is a RED HERRING for the active cross_visibility failure.**
   Reproduced cross_visibility FAIL in 13s with ZERO corruption (no EFSBADCRC/EFSCORRUPTED/corrupt
   dir block/shutdown/double-free/verifier errors on any of 4 nodes). The sess52 corruption did NOT
   reproduce (intermittent / rarer mode). Only error-ish line: INACT-SKIP-STALE ×1/node = sess47
   protective fix WORKING.
   - **`disk_differs=1` is an ARTIFACT**: at write-back time it's trivially true (in-core=new,
     disk=old). The P88 fires are numrecs=2 tiny extents (start=9 len=7 → 10/6 → 11/5) = NORMAL
     nearly-full small test-AG steady state, NOT the numrecs=1 pristine-revert it was built for.
     New fields: uniformly `in_ail=1 dirty=0 pin=0 delwri=0 buf_gen==pag_gen`.

2. **Exact failure: `node4.txt` invisible to nodes 1,2,3** (results log: "[FAIL] Node N cannot see
   node4.txt"). node1/2/3.txt visible everywhere w/ correct content; node4 sees all 4. Only the
   highest-id node's dirent is universally invisible — a pure dirent-visibility miss after sync +
   barrier + sleep 2 (deterministic, not a timing race).

3. **It is a SHORTFORM-directory inode-reload miss.** The cross_visibility dir has 4 tiny entries →
   XFS_DINODE_FMT_LOCAL (shortform): dirents stored INLINE in the dir inode literal area, NO separate
   dir data blocks (proof: xfs_dir2_readdir.c:537-538 returns via xfs_dir2_sf_getdents before any
   block read). **This is why DIR-STALE-SKIP=0 AND P-H18=0 on all readers**: the xfs_da_read_buf /
   b_mxfs_dir_gen invalidation hook (xfs_da_btree.c:2894) ONLY fires for XFS_DATA_FORK BLOCK reads —
   it never runs for shortform. So node4 visibility depends on the reader having a fresh DIR INODE,
   not a fresh dir block. All sess43-52 dir-BLOCK coherency work is irrelevant to this mode.

4. **reload CAN refresh shortform; the bug is reload NOT FIRING.** `mxfs_dlm_reload_inode`
   (xfs_mxfs_dlm.c:1097) calls `xfs_inode_from_disk(ip, dip)` which reparses the LOCAL data fork
   (inline dirents). So if reload fired, node4's entry would refresh. reload fires ONLY on slow-path
   ACQ-FRESH (xfs_mxfs_dlm.c:1925), which requires the reader's cached dir-inode DLM grant to be
   dropped + re-acquired fresh. The reader is instead serving the dir from a FAST-PATH cached PR
   re-grant (no ACQ-FRESH → no reload → stale in-core shortform dir missing node4).

## Next session (clear RULE-4 step)
Enable mxfs.instr=1, rerun cross_visibility, count on readers: P13-INSTR ACQ-FRESH vs P63-INSTR
FAST-PATH-DIR for the cross_visibility dir inode at verify time. Confirm fast-path (no reload).
FIX HYPOTHESIS: on a dir-inode (S_ISDIR) fast-path re-grant where a BAST was pending/deferred since
last hold (D9-pin path xfs_mxfs_dlm.c:1760, or the cached-mode fast path ~1780), FORCE
mxfs_dlm_reload_inode. Cheap (one inode-cluster read) — does NOT hit the sess43 timing wall (that was
FUA re-reads of ALL dir DATA blocks; shortform reload is a single inode-cluster read). Then reset4 +
rerun cross_visibility FOREGROUND.

Criteria NOT met (cross_visibility still fails). Marker not written. State head = sess53 (state.md).
See [[sess52_lessons]] (refuted concurrent-EX; this session refutes the bnobt framing too),
[[sess46_lessons]] (gen-frozen no-op branch — same shape, different domain),
[[sess48_lessons]] (reused-inode stale cache — INACT-SKIP-STALE is its protective cousin).
