---
name: sess17-ccloop-relflush-sidecar-fix
description: sess17 (ccloop 4eef1f39): FIXED cwr .md5-sidecar empty (RELFLUSH, verified 4/4 on clean cluster). Then exposed rename_visibility flaky empty-content…
metadata:
  type: project
---

## sess17 (ccloop 4eef1f39) — cross_write_read FIXED; rename_visibility epoch guard built

Tree = sess111-level + sess116 fixes + ccloop sess16. sess116 had reached
cache_coherency 3/4.

### FIX A — cwr .md5 sidecar empty-read (build 7BBF740C → folded in, KEEP, VERIFIED)
Root: bast_process set i_dlm_mode=NL (line ~1856) BEFORE the reg-durable
di_size flush (~2195) → sess119 P119 guard skipped writing di_size
(P119-NONEX-FLUSH-SKIP) → peer FUA-read di_size=0 → empty. Fix: per-inode
iflag MXFS_IF_DLM_RELFLUSH (1U<<18, xfs_inode.h); bast_process sets it (reg
only) around the reg-durable xfs_iflush_cluster loop, clears at
reg_durable_done; P119 guard adds `&& !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH)`.
**Verified: on a CLEAN freshly-power-cycled 4-node cluster, ALL 4
cache_coherency sub-tests PASS** (cross_visibility, rename_visibility,
unlink_visibility, cross_write_read). Minimal repro (test1 writes 33B no-fsync,
test2 cats) PASSES.

### CRITICAL TEST-INFRA LESSON
cache_coherency is FLAKY on a CONTAMINATED cluster. After multiple back-to-back
runs, nodes DROP their mount (test4/test2/test3 went NO-mount, no shutdown/oops
— just evict-ring churn) → invalid runs that look like data loss. ALWAYS full
virsh destroy+start ALL 4 nodes, then reset4.sh, before trusting any cc result.
The criterion's own teardown+remount can also flake to 2/4 mounted.

### FIX B — rename_visibility flaky empty-content (build C3B5DFE4, BUILT, NOT TESTED)
After FIX A, rename_visibility is FLAKY: PASS(2m27s, slow), PASS(26s), FAIL
80-120/240(20s, fast). Failures = `Content preserved... actual=''` (file exists,
di_size=0). Slow runs pass, fast runs lose content → timing race.
PROVEN root (P-IRESURRECT detector, xfsaild flush): BIDIRECTIONAL inode-reuse
ghost, BOTH with dlm_mode=5(EX) so sess119 P119 guard misses them:
 - content-loss: incore_mode=00 disk_mode=0100644 incore_gen=disk_gen+1
   nlink 0/1 → xfsaild flushes FREED in-core ghost OVER live disk inode →
   di_size=0 on SHARED LUN → all nodes (incl owner) read empty.
 - resurrection: incore_mode=0100644 disk_mode=00 (peer-freed) → would resurrect.
Gemini (RULE 5) gave the DLM-epoch LINEAGE guard (refuted gen-comparison; the
freed-ghost and legit-delete signatures are mathematically identical, need
external lock-lineage state):
 - new fields u64 i_mxfs_ex_grant_seq + i_mxfs_dirty_seq (xfs_inode.h), inited 0
   in mxfs_dlm_inode_init; global atomic64_t mxfs_ex_epoch=1 (xfs_mxfs_dlm.c).
 - stamp ex_grant_seq = atomic64_inc_return(&mxfs_ex_epoch) at EVERY transition
   INTO EX: the 3 `if (mode > i_dlm_mode)` grant sites (replace_all) + grant_local_new.
 - stamp i_mxfs_dirty_seq = i_mxfs_ex_grant_seq in xfs_trans_log_inode (libxfs).
 - GUARD in xfs_iflush_int (xfs_inode.c) AFTER the P119 EX check: if multinode
   && magic && !RELFLUSH && dirty_seq != ex_grant_seq → set ISTALE_CAW, error=0,
   skip (log P17B-EPOCH-GHOST-SKIP). Same continuous tenure (legit delete / new
   first flush) → equal → flushes. Yielded+retook EX (ghost) → mismatch → skip.
Gemini also suggested Layer 2 (FUA-validate-on-DLM-grant → taint ghost) if the
reader-side empty persists after Layer 1 — NOT yet implemented.

### NEXT SESSION (build C3B5DFE4)
1. Full virsh destroy+start ALL 4; reset4.sh 4; confirm C3B5DFE4 on all nodes.
2. Run rename_visibility 5-10× (MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests
   tests/run_tests.sh --nodes 4 --phase cluster --test test_rename_visibility ...).
   Confirm no more `actual=''`; grep dmesg P17B-EPOCH-GHOST-SKIP (should fire on
   the ghost, NOT on legit files — if it fires on legit files there's data loss).
3. If epoch guard does NOT catch it (ghost held EX continuously, no re-acquire),
   add Gemini Layer 2 (FUA-validate-on-grant taint). 
4. Then run cache_coherency.sh, then full verify_ship.sh end-to-end for the marker.
Marker NOT written.
