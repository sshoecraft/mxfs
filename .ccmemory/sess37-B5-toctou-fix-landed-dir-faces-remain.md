---
name: sess37-B5-toctou-fix-landed-dir-faces-remain
description: sess37: landed B5 inactivation TOCTOU fix (build 658CCD35, drop !local_unlink) for the bnobt double-free shutdown face. dir_reuse 2/tcp still flaky o…
metadata:
  type: project
---

## sess37 — B5 TOCTOU fix landed; dir-block faces remain the blocker

**Build 658CCD35** = A695EC5C + the B5 inactivation TOCTOU fix. Criterion (full ./run.sh 2 tcp) NOT met.

### FIX LANDED (xfs_inode.c ~2960, KEEP-pending-validation):
B5 (`mxfs_b5_nolock`) — dropped the `!mxfs_local_unlink` requirement. Rationale (PROVEN root,
[[sess37-bnobt-is-doubleFREE-stale-bmap-not-doublealloc]]): the bnobt double-free shutdown is a STALE
cached inode (P47-INACT inact_ino=2099107, disk_di_mode=0, disk_gen=incore_gen+1) inactivated by a node
that could NOT acquire the per-inode EX (peer holds it / is reusing the number). MXFS_IF_LOCAL_UNLINK
LEAKS across inode-number reuse (set when this node unlinked the prior incarnation, never cleared
because the stale copy wasn't reloaded), so the old B5 (`!local_unlink`) fell through, the racy
mutex-less disk read at CHECK time saw the inode still gen-G/live (B1/B2 missed), and the peer
freed+reused it in the post-check window → double-free. NEW B5: when the EX acquire FAILED and we don't
hold EX (outside log recovery), SKIP regardless of local_unlink — we have no authority and the disk
read is untrustworthy. SAFE: a node's OWN live files acquire EX cleanly (mxfs_inact_dlm_locked=true) so
B5 never fires for them; it fires only when a PEER holds EX = the stale-copy case that MUST skip.

### VALIDATION STATUS — UNPROVEN this session (flaky, B5 never fired in 2 runs):
- Run1 (MHT=300, B5): **PASS** (instr off — real, not masked). Run2: **FAIL** but NO shutdown
  (readdir=0 count=0; ltbno markers were pre-run dmesg-ring residue). INACT-SKIP-STALE=0 both runs.
- The shutdown face was ~1-in-6 pre-fix; 0-in-2 post-fix is consistent with BOTH "B5 fixed it" and
  "flaky miss". NEXT: run ≥6× to confirm shutdowns eliminated; run FULL `./run.sh 2 tcp` to confirm B5
  does NOT regress the other 16 tests with inode leaks (the risk of dropping !local_unlink — a transient
  EX-fail on a legit inactivation would skip→leak to the AGI iunlink list, recoverable but watch it).

### REMAINING BLOCKER = the two dir-block faces (flaky, NOT inode-inactivation):
1. **DATA loss** (readdir<200, node1_f1..fN early files gone from data blocks). Refuted: datainit
   clobber (benign), stale bmap (P37=0), evict-keep-stale-DATA (P37D-KEPT-STALE-DATA=0), read-hook
   retry, allocator-over-inode (sess55 P55=0). Mechanism still open: a dir DATA block (block 0) loses
   node1's early dirents durably; NOT a kept-stale data block. Candidate: dir-block double-alloc
   (block-0 daddr reused — P55 only checks inode chunks, NOT dir-block-over-dir-block) OR a write that
   never lands. NEXT: extend the alloc-over check to dir-block magic (XDD3/XDB3) at the data-alloc site.
2. **LEAF-HASH hole** (readdir=200 lookup_fail, node1_f47-50.md5). The evict KEEPS an undurable stale
   leaf (P21S-EVICTSKIP-LEAF fires) → RMW drops the peer's hashes. Recovery needs a MERGE/rebuild
   (mxfs_dir_rebuild_leaf_from_data) but dir_leaf_rebuild=1 SHUTS DOWN (data-over-inode-cluster
   double-alloc, sess30/55 — NOT B5-fixable, confirmed this session: B5+rebuild=1 → readdir=0 ×39).
   Chicken-and-egg: the leaf merge needs the alloc-coherency fixed first.

### Tooling: tests/drc_cap2.sh (instr OFF). Slice pre-run ring via the stream-start `lines=NNNN`.
Markers: drc-FAIL, readdir=0 (shutdown), INACT-SKIP-STALE (B5), P21S-EVICTSKIP-LEAF, P47-INACT.
Reset nodes (umount -l + rmmod) between runs after any shutdown. Marker NOT written.
