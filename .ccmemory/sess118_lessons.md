---
name: sess118_lessons
description: sess118 — AG-meta hard-barrier REFUTED (corruption); cache_coherency corruption root = inode RESURRECTION at xfs_iflush; fix = MXFS_IF_FIRST_FLUSH ga…
metadata:
  type: project
---

# sess118 (ccloop run 4eef1f39, s10)

## Marker NOT written. Build `DF34891E` built+compiles, NOT deployed/tested.

## REFUTED (RULE 4): the approved AG-meta hard-barrier (sess117 step 1)
Generalizing the release-side evict in `mxfs_dlm_ag_drain_meta_buffers` from
bnobt/cntbt to ALL AG-meta (agf/agi/inobt/finobt) **REINTRODUCED the bnobt
double-free** (`ltbno+ltlen>bno` shutdown) AND a 129s rename. Evicting AGF
desyncs agf_freeblks/longest + btree-root cache from the bnobt/cntbt leaves.
REVERTED to bnobt/cntbt scope. Gemini's rule: evict on ACQUIRE (safe — buffers
durable from peer's release), NOT release. NOTE: acquire-side
`mxfs_dlm_invalidate_ag_meta` ALREADY invalidates ALL AG-meta comprehensively
(no P47/P14 skips fired) — so AG-meta coherency is NOT the residual blocker.

## PROVEN ROOT (RULE 4) of the cache_coherency corruption-shutdown→stall→timeout
unlink_visibility (and the create storm) shuts a node down via `xfs_dialloc`
→ EFSCORRUPTED (-117 badmagic) → `xfs_trans_cancel` on a DIRTY trans →
"Corruption of in-memory data" → FS shutdown. That shutdown hangs peers on the
test barrier → 200s+ timeout. Probes: `P-CREATE-ERR1 dialloc/icreate err=-117`,
`P-CR62 new_ino=0 disk_di_mode=0xFFFF verdict=disk-read-err/badmagic`.
The badmagic is DOWNSTREAM of **INODE RESURRECTION**: `P-IRESURRECT` (sess102
detector, comm=xfsaild) fires immediately before — xfsaild's `xfs_iflush` copies
a LIVE in-core inode (mode=0100644,nlink=1) OVER a peer-FREED on-disk dinode
(mode=0,nlink=0,disk_gen≠incore_gen), resurrecting a dead inode → inobt/finobt
inconsistency → next dialloc badmagic. Mutual exclusion HOLDS (P106-STALE-EX=0);
release-side iflushes the dir inode durable; acquire reloads it (P105 fmt=2/4096
correct). So the bug is the xfsaild WRITE-side resurrection, not read coherency.

## FIX (built DF34891E, Gemini RULE-5 validated, UNTESTED): MXFS_IF_FIRST_FLUSH
Guard in `xfs_iflush` (xfs/xfs_inode.c, just before xfs_inode_to_disk): if
multi-node + valid disk magic + **!MXFS_IF_FIRST_FLUSH** + !INEW + `disk_gen !=
incore_gen` → SKIP the content copy (set XFS_ISTALE_CAW, error=0, goto flush_out)
so we don't resurrect; the peer's on-disk inode (already in the buffer) is
preserved and the AIL releases our ghost without a write.
- `MXFS_IF_FIRST_FLUSH` = `(1U<<17)` in xfs_inode.h; set in xfs_icache.c
  xfs_iget_cache_miss when `flags & XFS_IGET_CREATE` (this node allocates a new
  incarnation); cleared on first flush.
- WHY the flag: XFS di_gen is RANDOM (xfs_ialloc_inode_init stamps one per-chunk
  gen across all 64 slots — observed disk_gen=3283210591 identical; then
  xfs_init_new_inode prandoms again per alloc). So `disk_gen vs incore_gen`
  ordering is MEANINGLESS for new inodes. Earlier discriminators tried+REFUTED:
  `disk_gen != incore_gen`, `disk_gen > incore_gen`, `disk_mode==0 && incore!=0`
  — ALL false-positive on new-inode FIRST flush (disk slot still chunk-init,
  INEW already cleared by async xfsaild) → file never persisted → "cannot see
  node3.txt" + AIL stall (245s/125s). The flag makes `disk_gen != incore_gen`
  reliable ONLY after our own first flush stamps our gen.

## VERIFIED this session on the gen-only build (45D62BFC): the guard CONCEPT works
With the guard active, **shutdown=0, ltbno=0 on ALL nodes** (corruption ELIMINATED)
— previously a node always crashed. The only remaining problem was the new-inode
false positive (now fixed by the flag). So the resurrection guard is the right
lever for the corruption half.

## NEXT SESSION (concrete)
1. Deploy DF34891E: virsh destroy+start ALL 4 (nodes wedge on FS shutdown — rmmod
   hangs, reset4 RESET_FAILs), wait SSH, `reset4.sh 4`, confirm srcversion.
2. Run cache_coherency ×3. EXPECT: no shutdown/ltbno, P118-IRESURRECT-SKIP fires
   only on TRUE ghosts (NOT on new inodes — check skip inos aren't freshly-created
   files), cross_visibility PASS again (the false-positive killer is fixed).
   Healthy total ~20-60s; a 200s+ run = still stalling = a node still shutting down.
3. If a visibility/lost-update RESIDUAL remains (no shutdown but a file invisible),
   that's the dir-block lost-update half — separate from this corruption fix.
4. Gemini's deeper fix (do later if residual): gate iflush on i_dlm_mode==EX/PR &&
   state==CACHED, and make the BAST/revocation path take xfs_iflock(ip)
   (XFS_IFLUSHING) before granting to a peer (close the iflush-vs-BAST race).
   Also investigate WHY a node holds cached-EX while a peer freed the inode
   (DLM split-brain on inode locks under the create storm).

## TIMING: run cache_coherency with ~200s cap for DIAGNOSIS only; healthy is fast.
Slow = FAIL. See [[timing-timeouts-must-match-test]] [[sess117_lessons]].
</body>
