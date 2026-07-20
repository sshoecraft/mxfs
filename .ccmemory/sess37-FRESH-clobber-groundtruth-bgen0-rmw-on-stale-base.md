---
name: sess37-FRESH-clobber-groundtruth-bgen0-rmw-on-stale-base
description: sess37 FRESH dataclobber=1 ground-truth (build 24946150): real loss = bgen=0/stale=1 RMW/rebuild-on-stale-base; daddr=120 rm clobbers are FALSE POSIT…
metadata:
  type: project
---

## sess37 — FRESH P-DATACLOBBER-SKIP ground-truth (current build 24946150, dataclobber=1 detect-only, clean 8-node drc). CORRECTS the prior "bgen==dir_gen" framing.

### THE CLOBBERS SPLIT INTO TWO CLASSES (299 events, comms: rm=226, bash=32, dd=27, xfsaild=14):

**CLASS 1 — FALSE POSITIVES (the majority, daddr=120 = block-0):**
`kind=data owner=131 daddr=120 buf_cnt=154 disk_cnt=155 bufgen=9 dirgen=9 mode=5 real_mode=5 in_txn=0 in_ail=1 bdirty=0 pin=0 incarn==bincarn stale=0 comm=rm` — buf_cnt DECREASING (154,153,152,151...), disk_cnt always buf_cnt+1. These are the **rm-rf teardown removing entries one-by-one**: the buffer has the entry removed (ahead), disk lags by one until the removal destages. disk_cnt>buf_cnt here is EXPECTED/legit, NOT a clobber. **THIS is why dataclobber>=2 enforce was CATASTROPHIC (lookup_fail=150): it skipped these legit rm removals.** stale=0 (bgen==dir_gen) because rm re-reads block-0 each removal.

**CLASS 2 — THE REAL LOSS (data/leaf blocks, comm=dd/bash/xfsaild):**
- `kind=leaf daddr=4186520 buf_cnt=117 disk_cnt=379 bufgen=0 dirgen=35 mode=5 real_mode=5 in_txn=0 in_ail=1 bdirty=0 pin=0 stale=1 comm=dd` — a STALE PARTIAL LEAF (117 hash entries) about to be written over the peer's FULL leaf (379) → would drop ~262 (sess12 leaf-clobber family). Repeats at daddr=4186520.
- `kind=data daddr=41864552/96288376 buf_cnt=1 disk_cnt=1 bufgen=0 dirgen=42 stale=1 comm=bash/dd` — content-divergent equal-count (fresh-ish 1-entry blocks).
- Various data daddrs (14652640, 8372968, 2093296...) — the readdir-loss data-block clobbers.

### KEY CORRECTION: the REAL loss clobber has **bufgen=0 (stale=1)**, NOT bgen==dir_gen. bgen=0 = the buffer was NEVER coherently re-read (re-read/init stamps bgen=current; bgen=0 = evicted-not-reread OR get_buf'd-fresh-without-read). It carries un-landed local content (likely undestaged: logged_seq!=written_seq) so it CANNOT be safely dropped (that's why sess37 v1's clean+destaged skip fired only 2x — these are UNdestaged). This is an **RMW/REBUILD-ON-STALE-BASE**: a dir block (esp. a LEAF created/rebuilt via xfs_dir2 get_buf during block->leaf conversion or leaf split) is modified on a base that was never coherently read (bgen=0), so it lacks the peer's entries, and writing it durably drops them.

### WHY existing guards miss it:
- The read-path bgen<dir_gen invalidation (xfs_da_btree.c) re-reads stale blocks ON READ — but a block obtained via **xfs_da_get_buf (leaf conversion/split/rebuild, no read)** keeps bgen=0 and is modified WITHOUT a coherent read → RMW on stale base.
- grant_evict evicts on EX acquire but the get_buf rebuild path re-creates the stale base after.
- dir_ex_write_guard only fires for NON-EX-holders; these are mode=5 EX.

### THE FIX DIRECTION (read/acquire-side, NOT write-suppression — write-side DATA suppression is categorically the corruptor, proven sess23/33/37): ensure NO dir block is MODIFIED on a bgen=0/stale base. Candidates:
1. Before any dir block RMW (or at the get_buf rebuild/conversion sites in xfs_dir2_leaf.c / xfs_dir2_node.c / xfs_dir2_block.c), if the block is bgen<dir_gen (or bgen=0 with a valid on-disk image), force a coherent FUA re-read of the base FIRST so the rebuild/modify starts from the peer's durable image. The LEAF rebuild (buf_cnt=117 over disk 379) is the smoking gun — the leaf is rebuilt from a stale data scan.
2. Investigate the leaf at daddr=4186520: buf_cnt=117 vs disk 379 → the leaf-hash index is rebuilt from a partial/stale set. mxfs_dir_rebuild_leaf_from_data (xfs/libxfs/xfs_dir2_leaf.c, sess22) may rebuild from a stale data fork. Make the rebuild read the coherent disk leaf/data first.

### Harness unchanged. dataclobber=1 = detect-only (logs P-DATACLOBBER-SKIP, still writes). Lost names this run: node2_f43.md5 (round3), node7_f46.md5 (round20) — single .md5 entries, durable all-ranks. See [[sess37-HEAD-handoff]] [[sess12-leaf-clobber-stale-aild-reflush]] [[sess40-CORRECTION-production-DOES-fail-bugA-real-at-dirwr0]].
