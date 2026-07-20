---
name: sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage
description: sess42 SYNTHESIS: dir_reuse loss = logical-block0 split (node1 fsb15/node2 fsb14) from BOTH nodes converting sf->block per incarnation. Connects to s…
metadata:
  type: project
---

## sess42 SYNTHESIS — dir_reuse_coherency 2/tcp loss = logical-block0 SPLIT from double shortform->block conversion

### THE BUG (clean-dmesg confirmed, build E8C6B4B6): the dir's LOGICAL block 0 ends up at DIFFERENT physical blocks on the two nodes — node1 ALWAYS fsb=15 (daddr 120), node2 sometimes fsb=14 (daddr 112). At cold verify the home dinode's logical-0 points at whichever flushed last (node2's), orphaning the other's block (node1_f1..f14). lookup_fail=0 (leaf hash still maps to logical-0).

### LINEAGE — this is the SAME blocker as sess28/31/36/37 (the "first-block / node1_f1..f14 durable loss"), viewed via the extent map:
- [[sess36-PROVEN-datainit-zeroes-live-block0-root]]: xfs_dir3_data_init ZEROES block0 (daddr 120) holding 14 live dirents. P31E-DATAINIT-ABA detector (xfs/libxfs/xfs_dir2_data.c:819). P32B-DOUBLEMAP (no-I/O in-core scan, same gate) was 0 => NOT an intra-dir double-alloc; the init re-creates a block0 the dir already materialized.
- sess37: argued most P31E zeroes are BENIGN (prior-incarnation freed-block reuse; on-disk inode shortform at the clobber). The CURRENT-incarnation case is the real loss. The discriminator (current vs prior incarnation of the SAME reused ino) is the hard part — the dir3 block header has owner ino but NO generation, so disk content alone can't tell.
- KEY CONSTRAINT: P31E's decisive proof needs a SYNCHRONOUS disk read per init which PERTURBS the create-heavy timing and flips the test pass/fail (heisenbug). Same with mxfs.instr=1. So the decisive instrument must be NON-PERTURBING (no per-op I/O).

### MECHANISM (best model): the dir is rm-rf'd + recreated each round (new incarnation, di_gen bumped). It starts SHORTFORM. BOTH nodes write 50 files concurrently (serialized by dir-inode EX — P-DOUBLEGRANT=0, no concurrent EX). The shortform overflows and CONVERTS to block format (xfs_dir2_sf_to_block, allocates block0). If BOTH nodes convert the SAME incarnation from their own shortform base (the second did NOT adopt the first's already-materialized block0), each allocates block0 at its affine physical block (node1->fsb15, node2->fsb14) => logical-0 split. The second converter fails to adopt because its EX-acquire reload read a STALE shortform base (first's conversion not yet on the home dinode block, or a cached shortform) — NOT P91-RELOAD-PROTECT (0x on node2 at the failure) and NOT release-durability ([[sess42-ROOT-dir-block0-divergent-alloc-dinode-not-durable]]: C5BD4E04 forcing block/leaf dinode durable at release did NOT fix it).

### THIS SESSION'S DECISIVE NON-PERTURBING DETECTOR (build B8C2149E): P42-SFCONV at xfs_dir2_sf_to_block entry (xfs/libxfs/xfs_dir2_block.c ~1182) — always-on capped, NO disk I/O. Logs ino, sf_size, sf_count, dir_gen, loaded_gen, dlm_mode, **i_gen (incarnation)**, addname, comm on EVERY conversion. DECISIVE TEST: in a failing round, find ino=131's i_gen; if BOTH test1 AND test2 have a P42-SFCONV with that SAME i_gen (no rm-rf between) => double-conversion CONFIRMED => fix = make the second sf_to_block ADOPT the peer's block0 (FUA-verify on-disk format; if already block-fmt for this incarnation, reload+append, do NOT convert). [Capture running at handoff: b9zbb6vwj.]

### TREE: B8C2149E = E8C6B4B6 (held-check stall fix, KEEP, [[sess42-FIX-held-check-mode-blind-false-negative-PR]]) + P42-SFCONV detector + drc_cap2 dmesg-clear fix ([[dmesg-follow-ringbuffer-staleness-trap-drc-cap2-fix]]). Also residual ~6s PR->EX conv-deadlock stall (P-CONVBLK-DENY/P34-ACQ-SLOW dur_ms~6000, 3x/run) — separate RULE-0. See [[sess42-DECISIVE-clean-round19-block0-double-alloc-at-sf-to-block]].
</body>
