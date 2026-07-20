# Deferred-publish design (sess43, Gemini RULE-5 consult)

## Problem
rsync_paired: 4-node parallel rsync of disjoint subtrees. Worst node 28.5s vs
target 5.5s (1.2x single-node XFS). PROVEN decomposition (solo rsync, peers idle):
- multi-node solo ~20s vs single-node 4.8s => ~16s coordination overhead.
- INODE-LOCK CAW = ~8.5s: 9216 disk CAW round-trips (one per new inode), ~900us.
  DOMINANT cost.
- AG-LOCK CAW = 0 (node-affine alloc works, AG grant stays cached).
- FUA reads <256 (negligible; prior FUA theory REFUTED).
- ~6-8s unexplained gap (not inode CAW, AG CAW, FUA, or printks).

## Fix: deferred / lazy publish of new-inode DLM slots
- xfs_iget cache-miss + XFS_IGET_CREATE: grant inode lock LOCALLY (i_dlm_mode=EX,
  state=CACHED, i_dlm_unpublished=true), NO disk CAW, NO slot. Add to a single
  per-mount `unpublished_inodes` list. All later local ops fast-path.
- Recursive deferral is safe (discovery is strictly top-down: a peer reaches an
  inode only via its parent dir, or via inobt under AGI). Defer BOTH dirs+files.
- PUBLISH TRIGGER (synchronous, BEFORE releasing the lock): on a BAST for ANY
  directory inode OR ANY AGI/AG lock, drain the ENTIRE unpublished list (real CAW
  acquire EX for each). Race closed: peer is blocked on the BAST'd lock, cannot
  reach any child until we release; we publish all-unpublished first.
- In rsync_paired (disjoint subtrees) zero dir/AGI BASTs from peers => list never
  drains => ZERO inode CAW => near single-node speed.
- In cache_coherency, BASTs fire => drain publishes => correctness preserved.
- Publish ONLY on-demand (BAST) or local eviction. NOT at iflush (would do all CAWs).
- Local mutual exclusion: deferred state must still take the normal local
  down_write(&ip->i_lock) at xfs_ilock (it does — rwsem taken regardless of DLM
  return). The earlier inobt-corruption from broad skip was broken local exclusion
  / skipped buffer init, NOT the disk CAW itself.

## LRU slot reclaim (scaling fix, synergizes)
- Cached EX inode grants never release their slot until evict/BAST => slot table
  fills (65536) => find_slot probe chains lengthen => slowdown => wedge.
- On local eviction (xfs_inactive/destroy_inode): if i_dlm_unpublished, just drop
  (zero disk slots, no release CAW). If published, release CAW (or LRU + scavenger
  when table >25% full).

## Gap (~6-8s) hypotheses to instrument next (per RULE 4)
1. multi-node synchronous log forces (xlog_force XFS_LOG_SYNC) on dir/inode-alloc
   txns — count xlog_force single vs multi-node.
2. normal (non-FUA) buffer read count spike in multi-node — blktrace read count.
3. workqueue context-switch overhead per lock.
NOTE: deferred-publish skips the whole slow path (CAW+reload+buf-inval) for new
inodes, so it may shrink the gap too. Measure after implementing.

## Status: design saved, implementing PHASE 1 (deferred-publish).
