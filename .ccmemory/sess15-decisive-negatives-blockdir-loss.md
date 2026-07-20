---
name: sess15-decisive-negatives-blockdir-loss
description: sess15 (2/tcp) DECISIVE NEGATIVES on block-dir concurrent-create loss: NOT master double-grant, NOT MHT window, NOT mastership flap. Loss is CONTIGUO…
metadata:
  type: project
---

## sess15 build 3017D9DF (deployed, dirwr=1 sf_merge=1). Reproduced block-dir concurrent-create durable dirent LOSS via tests/cc_blockdir_probe.sh (loss on iter 5-15, fast). Criterion `./run.sh 2 tcp` 100% NOT met. Marker NOT written.

## DECISIVE NEGATIVES (RULE 4, instrumented, this build):
1. **NOT a DLM master double-grant.** Master-side single-clock detector `P-DOUBLEGRANT` (dlm/dlm.c dg_grant_ex, dg_shadow table) fired **0** times at a loss. `P-STALEMASTER-GRANT` (mastership flap) = **0**. The cross-node P106-EXGRANT-before-EXREL "overlap" I first saw (~4.5ms) is CLOCK SKEW between test1/test2 (SSH latency masked precise skew; master detector is authoritative & skew-proof). So the gen-token double-grant fix (404BC55C) is HOLDING. Do NOT re-chase master double-grant.
2. **NOT the MHT batching window.** Set `inode_mht_ms=0` on both nodes (runtime, 0644) → loss STILL reproduced (iter5, 10 files lost). sess10-correction candidate (a) "serve EX-modify during MHT-defer while BAST pending" REFUTED as the cause. Restored mht_ms=50.
3. **1× P-CONVBLK-DENY** at the run (PR→EX upgrade conflict → EDEADLK → drop-through-BAST + reacquire). Comment says it fires "at a crash_consistency failure" — possible correlation, not yet proven causal.

## NEW CLUE — loss is CONTIGUOUS NAME RANGES: with mht=0, lost set was node2_f8,f9,f10,f11,f11.md5,f12,f13,f13.md5,f14,f15 (8 consecutive data files f8-f15 + 2 md5). A contiguous range ≈ a whole dir DATA/LEAF block's worth of entries → points at BLOCK/ALLOCATION-level corruption (AG free-space double-alloc → dir block shares a daddr, sess39/42/47 family), NOT per-dirent cache staleness. All lost files are test2's OWN (test2 created them, test2 ALSO can't see them = durable on shared LUN).

## OTHER FACTS: per-node i_dlm_dir_gen DIVERGES wildly (test1 gen=4 vs test2 gen=33 for same reused ino 4238) — it's a LOCAL per-node slow-acquire counter, NOT a cross-node coherency signal. modify_refresh evict is gated on local gen!=evicted_gen, so it only evicts on THIS node's fresh slow-acquire. mxfs_dir_flush_data_blocks (bast release) DOES bwrite in-AIL/pinned/dirty dir blocks (durable), skips evict-invalidated (!XBF_DONE) clean blocks. mxfs_v5_dlm_inode_held = NO-OP on TCP (P106/P108 slot detectors dead on TCP).

## NEXT (RULE 4): test the BLOCK-ALLOCATION double-alloc hypothesis. Instrument dir-block ALLOCATION (xfs_bmap/xfs_dir2 grow) on concurrent create-into-shared-dir: do both nodes allocate the SAME daddr for new dir blocks? Existing P81-DEXT (xfs_inode.c:2747,4141) + sess42/47 AG-gen fixes are relevant. Harnesses: tests/cc_blockdir_probe.sh (FAST, reproduces in <15 iter), tests/cc_doublegrant_probe.sh (master double-grant timeline), tests/cc_inode_timeline.sh (per-inode DLM event dump). [[sess14-cc-root-blockdir-concurrent-create-dirent-loss]] [[sess10-SYNTHESIS-handoff-and-final-target]]
