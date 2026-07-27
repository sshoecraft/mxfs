---
name: ccloop-c7ee71c6-sess7-B-ROOT-rebuild-ungated-leafread-relog-CC-GREEN
description: sess7 ROOT+FIX: mxfs_dir_rebuild_leaf_from_data ungated leaf_read = P14 storm (block dirs) + stale-leaf relog racing split = Defect A tear. Gate → CC…
metadata:
  type: project
tags: [root-cause, rebuild, leaf-relog, defect-a, defect-b, crash_consistency, P14, P-DACRC]
---

# sess7 part B — THE ROOT: ungated leaf-rebuild probe/relog; CC now green

## Root (RULE 4 disposition for Defect A + Defect B)
`mxfs_dir_rebuild_leaf_from_data` (libxfs/xfs_dir2_leaf.c:721, armed once per
cross-node tenure via MXFS_IF_DIR_LEAF_STALE in xfs_dir_createname) called
`xfs_dir3_leaf_read(geo->leafblk)` UNCONDITIONALLY for any EXTENTS-format dir:

1. **Defect B arm (P14-DABUF-HOLE)**: on a BLOCK-form dir (nextents=1,
   disize=4096) the read maps LEAF_OFFSET via xfs_dabuf_map WITHOUT HOLE_OK →
   corruption machinery fires (mark_sick + "Corruption detected" + P14 print +
   FUA hole-probe = ms each) on EVERY armed create → EUCLEAN storms during the
   early create phase, mark_sick side state, massive create latency. The
   ORIGINAL sess6-B Defect-B capture (dir 131 fmt=2 nextents=1 disize=4096 EX
   held) IS this signature.
2. **Defect A arm (torn da3 blocks)**: on a dir mid leaf→node SPLIT the
   rebuild leaf_read/RELOG raced the transition — relogging a STALE LEAF1
   image of a block that is becoming/became the da3 root node. The commit
   creates a legitimately-AIL-attached stale image which xfsaild + release
   drains then write at any gmode (the sess6 19×PR + 1×NL "crime" writes and
   the t6-danode AIL leak are all consistent with this producer). Interleaved
   with the real holder's split writes at the target (no cross-command SCSI
   atomicity) → CRC-torn hybrid on the LUN → EUCLEAN → shutdown cascade
   (sess6) / failed creates (192304Z: dd EUCLEAN at :20-21 = the 84
   durably-missing entries: exp=800 cnt0=pureLUN=direx=716).

**Fix (v0.11.98, srcver 02D5804CDD34C15FF16DF06)**: gate the rebuild on
`xfs_dir2_format(args,&frc) == XFS_DIR2_FMT_LEAF` (coherent, under held
ILOCK) before the leaf read. Block/SF/NODE/error → bail 0 (contract "no
repair this op").

## Verification (RULE 6)
- crash_consistency@8/tcp: **PASS 8/8 404/404 ×3** (22s/12s/11s wall vs
  58-61s before — probe latency gone). Counters across all 8 nodes ALL ZERO:
  CRC=0 DACRC=0 P14=0 P123=0 EUCLEAN=0 AILLEAK=0. **P123=0 means with the
  producer gone the fence has nothing left to suppress** (it stays as
  defense-in-depth + the FUA-arm gate).
- dir_reuse_coherency@8/tcp: PASS ×2, 1 intermittent FAIL (see below).
- Fence v1 + FUA gate (sess7-A entry) remain in the tree.

## OPEN
- **drc readdir transient undercount**: run 194432Z round=16 rank=1
  readdir=112/128 lookup_fail=0 missing=[] (re-probe found nothing missing =
  transient view; leaf hash intact). 1-of-6 runs today; pre-existing family.
  OPEN per RULE 6, needs its own RULE-4 loop (batch dir_reuse to repro).
- run 190758Z livelock mode (NO_TERMINAL_RECORD ×8, re-BAST suppress storm):
  not recurred in 5 runs since; unexplained nondeterministic mode — watch.
- test4 teardown "BUG mxfs_inode: Objects remaining on kmem_cache_shutdown"
  after the EUCLEAN-storm era unmount — likely P142-BWORK-LASTREF deliberate
  leak; untriaged.
- P-DACRC probe (new, xfs_mxfs_dlm.c ~17322 + da_btree verifier hooks): armed
  and ZERO-firing since the gate; keep for any recurrence — it classifies
  torn-on-LUN vs torn-in-flight vs cache/platter divergence at failure time
  with lineage crcs matchable against P-DIRWR.

## Next
Rung completion at final srcver (v0.11.98): full 8/tcp suite, then stale board
rows (fio_perf, fio_perf_vs_xfs, soak, tcp_dlm_scaling, fence_during_write,
fault_netpartition), then Phase B d_revalidate, 16/tcp, 32/4/2/1, caw/cawp/
cawd, QNAP physrig, final matrix (state.md priority list).
