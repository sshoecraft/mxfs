---
name: sess36-correctness-aba-dirblock-clobber-fix-plan
description: sess36: dir_reuse 2/tcp LAST blocker = ABA dir-block clobber (node1_f1..f12 lost). Read-hook+eager-evict both TRYLOCK-skip stale; eager-evict lacks A…
metadata:
  type: project
---

## sess36 — dir_reuse 2/tcp CORRECTNESS blocker: ABA dir-block clobber (mechanism + fix plan)

TIMING is solved (MHT=300, see [[sess36-timing-solved-mht300-and-stall-fixes]]). This is the
remaining face: durable dir-DATA-block loss. Build BC6D7A5E, FAIL nodes_pass=0/2 is now CORRECTNESS
(not timeout): drc-FAIL=1 round 15, both nodes readdir=188/200, missing EXACTLY node1_f1..node1_f12
(rank1's first 12 DATA files; .md5 + f13..f50 + all node2 entries survive). lookup_fail=0 → durable
on-disk content loss, both nodes agree. EXACT match to [[sess28-dir-data-block-RDMISS-first-block-clobber]].

### MECHANISM (strong, partly PROVEN):
ABA on the dir incarnation. Dir is rm-rf'd+recreated each round (new incarnation, SAME reused
daddrs). The first-wave dirents (node1_f1..f12) land in dir DATA block 0 (daddr 120). A node serves/
RMWs a STALE block-0 (prior incarnation or pre-f1..f12 base), clobbering them.
- **PROVEN read-side stale-serve**: `P34-TRYLOCK-STALE ino=131 blk=0 daddr=120 ... rc=-11` fires.
  The read-time invalidation hook (xfs/libxfs/xfs_da_btree.c ~3101) uses XBF_TRYLOCK and SKIPS on
  -EAGAIN (buffer locked by I/O or peer drain) → serves the cached STALE block → RMW base is stale.
- The read-hook HAS ABA bypass (xfs_da_btree.c ~3205-3227: owner_aba via
  mxfs_dir_data_buf_owner_mismatch, incarn_aba via b_mxfs_dir_incarn != VFS_I(dp)->i_generation;
  these bypass the dirty/in-AIL keep-guard) — but it only helps when TRYLOCK SUCCEEDS.
- The EAGER acquire-time evict (xfs/xfs_mxfs_dlm.c mxfs_dir_drain_evict_data_blocks ~3198, called at
  slow-path acquire ~8469) ALSO uses XBF_TRYLOCK (line ~3300, skip on fail) AND only evicts clean
  blocks (line ~3372: `!pinned && !dirty && !delwri && (!in_ail||!undestaged)`) — it LACKS the ABA
  bypass. So an ABA-stale dirty/in-AIL block-0 is NOT evicted at acquire either.
- GAP: ABA-stale block-0 slips both nets → stale RMW → f1..f12 lost.

### FIX PLAN (next session, RULE 4):
1. **(do first) PROVE the write clobber** — add the sess28 content-revert detector: before a
   xfs_dir3_data_buf_ops write, plain-read the on-disk block-0, compare live-dirent count; flag
   writing-FEWER-over-MORE. Confirms stale-RMW vs a write-side durability gap. (Distinguishes the
   two; my evidence is read-side only.)
2. **FIX**: add the ABA bypass to the eager evict (mxfs_dir_drain_evict_data_blocks ~3372) — evict an
   owner_aba/incarn_aba block even if dirty/in-AIL/delwri (NOT pinned — sess64 corruption). At slow-
   path acquire the block is usually unlocked (no concurrent create yet) so TRYLOCK succeeds there,
   unlike the read-hook under create contention. Mirrors xfs_da_btree.c ~3205-3227. Need the ABA
   helpers visible in xfs_mxfs_dlm.c (mxfs_dir_data_buf_owner_mismatch + b_mxfs_dir_incarn field).
3. If still lossy: the eager-evict TRYLOCK-skip itself — at slow-path acquire blocking is documented-
   safe (sess97 comment ~3324 "runs off CAW poll thread, process ctx"), so a BOUNDED retry (not a
   hard blocking lock — deadlock risk per the read-hook comment) on TRYLOCK-fail for ABA blocks.

### Flakiness: drc-FAIL across sess36 runs = 0,10,1,1 (D11B791A/7D7CBC37/BC6D7A5E-mht50/BC6D7A5E-
mht300). FAILS most runs — must be fixed, not run-around. Higher MHT did NOT fix it (round 15 @
mht300). MHT=1000 would serialize bursts (maybe fixes it) but blows the 300s budget (~+30s).
Run recipe: `export MXFS_EXTRA_MODARGS='inode_mht_ms=300'; bash tests/drc_cap2.sh` then
`python3 tests/drc_analyze.py /tmp/t1.log /tmp/t2.log` (slice off pre-run ring first). Marker NOT written.
