---
name: sess28-REFUTED-subset-guard-overfires-catastrophic-readdir316
description: sess28(ccloop) REFUTED dir_subset_guard=1: catastrophic readdir=316/800 (over-suppresses legit concurrent writes). The content-superset write check c…
metadata:
  type: project
---

## sess28 — dir_subset_guard=1 REFUTED (catastrophic over-suppression)

### Test: clean cluster, coherent=0 dir_subset_guard=1, DRC_ROUNDS=24
RESULT FAIL, wall=497s (slow), P26-SUBSET-SKIP fired (p26=1). drc-FAIL round=3 rank=1 **readdir=316 exp=800** lookup_fail=68, missing whole ranges [node1_f1, node2_f10..f19.md5, ...]. (The driver's rdmiss=0 was a FALSE reading — the mxfs-drc-RDMISS line rotated out of the dmesg ring under 497s of P26 spam; always read mxfs-drc-FAIL `readdir=N` for the truth, not the rdmiss counter.)

### WHY it over-fires (the fundamental flaw in the content-superset check)
mxfs_dir3_disk_has_extra_inum (pal/linux/xfs_buf.c) suppresses a dir-DATA-block write when the on-disk block holds an inumber the in-core image LACKS. But during CONCURRENT directory growth that is the NORMAL state: node1's in-core block has node1's fresh adds; the disk has node2..node8's concurrently-committed adds that node1 never saw. So node1's perfectly-legit write looks like "in-core is missing disk inumbers" → SUPPRESSED → node1's adds never land → readdir collapses to 316. P26-SUBSET-SKIP cannot tell a stale-revert from normal concurrent-growth lag. Same class as the refuted dir_stale_incarn_skip=1 (sess22) and the sess23 "suppression IS the corruptor" trap. KEEP dir_subset_guard DEFAULT 0.

### The real shape of the write-side loss (refined)
diff1=0 (read coherent at addname) + write-side loss means: node's in-core block is coherent AT ADDNAME TIME T1, but by DESTAGE time T2 a peer added more (node released EX, peer took it+added). The post-release destage writes the T1 image over the T2 disk → reverts the peer's T2 add. The EXISTING NL-release dirskip (P16/P17 mxfs_buf_xfsaild_skip_dir_write, default on) is SUPPOSED to catch an NL-released dir write but the loss persists at default → either the destage fires while still EX-held, or the predicate misses it. Both naive content-suppression (subset) and naive count-suppression over/under-fire. The correct fix is likely a MERGE at write time (union in-core ∪ disk dirents before write) OR true serialization (only the current EX holder writes, with a coherent base) — NOT a drop-suppression. A union-merge of dir DATA blocks at the write chokepoint (when disk has extra inumbers AND we're not the EX holder / superseded) preserves BOTH sets. CAUTION: sess21 union-merge of SHORTFORM had an offset-collision corruption bug (fixed by fresh monotonic offsets); a DATA-block union-merge must rebuild bestfree + offsets correctly.

### NEXT SESSION targets (write-side, RULE 4):
1. Instrument the dir-DATA write chokepoint to PROVE the T1-over-T2 revert: at submit of a dir-data block, FUA-read disk; if disk has extra inumbers (peer adds) AND in-core also has extra (our adds) = a MERGE case (not pure stale) → log P-MERGE-NEEDED. If disk-extra AND in-core-subset (no in-core extra) = pure stale rewrite → safe to suppress. Distinguish these two empirically.
2. If MERGE-NEEDED dominates: implement a content union-merge at the write chokepoint (preserve disk's peer dirents into the in-core image before writing), rebuilding bestfree/offsets. This is the only thing that preserves both concurrent writers' entries.
3. Also confirm whether node's destage is EX-held or NL-released at the clobber (P16 mode field) to know if the existing dirskip predicate is the gap.

### Keeper: build 52EED814 (dir_addname_coherent=0, dir_subset_guard=0, all sess28 levers OFF == prior keeper 164A6D5D behavior). See [[sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0]] [[sess23-ccloop-suppression-was-corruptor-3of4]] [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]].
