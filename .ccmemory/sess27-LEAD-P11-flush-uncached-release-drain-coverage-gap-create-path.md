---
name: sess27-LEAD-P11-flush-uncached-release-drain-coverage-gap-create-path
description: sess27(ccloop) STRONG LEAD: dir_reuse residual content loss correlates with P11-FLUSH-UNCACHED comm=dd — dir DATA blocks UNCACHED at the release-flus…
metadata:
  type: project
---

## sess27 — the release-drain coverage gap (P11-FLUSH-UNCACHED) is the leading concrete suspect

After refuting extent-map divergence, release-durability, read-side staleness, and concurrent-EX ([[sess27-REFUTED-four-mechanisms-residual-is-undetectable-content-lostupdate]]), the surviving root is an undestaged/uncovered dir DATA block served stale OR lost at release. Found the concrete gap:

### mxfs_dir_flush_data_blocks (xfs_mxfs_dlm.c:1599-1625): UNCACHED-block skip
The release drain walks the in-core extent map and, for each dir data block, `xfs_buf_incore()`. If the block is NOT cached, it `continue`s — "not cached => already on disk." The code itself flags this as a PROVEN HAZARD (P11-FLUSH-UNCACHED comment): "a just-committed dirent in an evicted-clean block is lost (durable single-dirent loss, node3_f45.md5)."

### Evidence (dirwr=1 round-7 capture, lost node5_f46.md5):
- P11-FLUSH-UNCACHED ino=131 comm=dd fires in the CREATE window (t=102..111) on ALL 8 nodes: r1=12 r2=32 r3=18 r4=93 r5=14 r6=21 r7=18 r8=33 (comm=dd only; comm=rm counts are far higher, 25546 on r1 — the rm phase).
- Same daddrs recur across nodes: off=0 daddr=120 (AG0 blk0), off=1 daddr=12559416, off=2 daddr=10466192, off=3 daddr=12559424 — dir data blocks in DIFFERENT AGs (node-affine alloc).
- P34-LEAF-DRAIN CACHED=0 also fires heavily (r1=600 r4=428 r6=547 ...) — LEAF/free blocks uncached at release too (Inv-1 leaf gap candidate, sess34).

### Interpretation (unproven — next session must confirm)
A node commits a dirent into dir data block B, but by its release-drain B is uncached → the drain skips B as "on disk." If B's committed content was NOT actually on the platter (evicted before writeback, OR the node's in-core off→daddr maps to a daddr it never cached because a peer's divergent alloc owns that logical block), the dirent is durably lost. The recurring daddr=120 (off=0) uncached on EVERY node hints at divergent off→daddr: each node's in-core off=0→120 but it cached a different physical block, so the flush of "120" finds nothing.

### REFUTED this session
- `dir_release_invalidate=1` (added to gen_per_handoff+extent_adopt): run1 PASS, run2 FAIL round=18 readdir=799 single-entry, normal speed (344s). Only evicts CLEAN+DURABLE blocks, so it cannot cover the undestaged/uncached case. Refuted as a fix.

### NEXT (sess28) — RULE 4, instrument-then-fix:
1. PROVE the P11-UNCACHED skip is the loss: at the uncached-skip for ino<=256, FUA-read that daddr from the platter and compare to what the in-core extent map expects (is the just-committed dirent absent on disk?). If absent → confirmed. 
2. If confirmed, FIX: when a dir DATA block is uncached at release-flush, do NOT assume durable — re-read it coherently and, if its content lacks our just-committed dirent (or the logical-block daddr diverges), force the inode-cluster + block durable via the canonical (lowest) daddr before unlock. Consider whether the off→daddr divergence (daddr=120 uncached everywhere) means the lowest-daddr-wins iflush_fence (mxfs_dir_iflush_fence, default 0) is actually needed here despite sess65 marking it inert.
3. Build/keeper unchanged: 965BDBD3 = gen_per_handoff(0) + extent_adopt(0) defaults; the working config is the 2 modargs. Pass rate this session (clean markers): ~3 PASS / 2 FAIL across the dirwr=0 + dirwr=1 + release_invalidate runs (rounds 7,13,18). Harnesses: tests/tcp/drc_catch3.sh (dirwr+NFS stream), drc_passrate2.sh (clears stale markers). Streams: tests/tcp/drc_cap/.
