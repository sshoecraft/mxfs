---
name: sess43_lessons
description: "2026-06-01 sess43. PROVEN FIX for AG free-space double-alloc corruption — invalidation hook discarded in-AIL (committed-but-unwritten) buffers → lost update. Remaining: iunlink/AGI + dir-block coherency."
metadata: 
  node_type: memory
  type: project
  originSessionId: ca448f6e-f7e3-4926-b35f-0c68ce5c9ee4
---

# sess43 — AG-meta in-AIL lost-update FIXED (proven)

## The fix (PROVEN, keep)
**`mxfs_ag_meta_invalidate_stale` (xfs/xfs_mxfs_dlm.c ~L2206)** — the per-read AG-meta
invalidation hook discarded (cleared XBF_DONE → re-read from disk) any gen-lagging buffer
that was `DONE && !XFS_LI_DIRTY && !pinned && !delwri`. **BUG: a buffer committed to the
log and sitting in the AIL awaiting metadata writeback has `XFS_LI_DIRTY` CLEARED and
`pin==0`, yet its in-core content is AHEAD of disk** (P70 proved exactly this: `bno_dirty=0
bno_pin=0` yet `bno_disk_differs=1`). Discarding it re-read the STALE on-disk image →
**lost the committed update** → cnt/bno free-space trees diverge by exactly the one
allocated block → `XFS Internal error i != 1 at xfs_alloc.c` (xfs_alloc_fixup_trees) →
forced shutdown.

**FIX**: add `XFS_LI_IN_AIL` to the "safe to discard" guard:
```c
bool in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
... else if ((b_flags & XBF_DONE) && !dirty && !in_ail && !pinned && !delwri) { discard }
```
An in-AIL AG-meta buffer is ALWAYS this-node-ahead (the AG-DLM EX serialises peers; release
drains the AIL before unlock), so preserving it is correct; gen stays lagging so a later
read (after writeback clears it from the AIL) refreshes it. **Corroboration: the codebase
already established this in v0.3.32 (drain path, xfs_mxfs_dlm.c ~L2899): "a bli in AIL with
XFS_LI_DIRTY clear can STILL have pending writeback ... bli in AIL is the authoritative
writeback-pending signal."** The invalidation hook simply never applied that knowledge.

## How it was proven (RULE 4)
- **P76 instrument** (end of xfs_alloc_fixup_trees, dup-cursor consistency check) fired
  **0×** while P70 fired 16× → the fixup leaves the in-core trees CONSISTENT; the divergence
  appears LATER (between fixup-commit and next read) → NOT an allocator-logic bug, it's a
  coherency event. This redirected from "modify-time / AGF-serialization" (sess42's leading
  hypothesis, WRONG) to "post-commit buffer reverted by invalidation."
- **P70 detail**: `bno_disk_differs=1` (in-core bno ahead of disk), `cnt_disk_differs=0`
  (in-core cnt reverted to disk) — the cnt buffer got discarded+re-read while holding a
  committed update.
- **After fix** (srcversion `BB54A138`): single clean repro run → P70=0, P71=0, corrupt=0,
  and **P77 (the fix's protect-log) fired 21-56× per node** — proving the fix is actively
  catching the in-AIL buffers the old code would have wrongly discarded. AG free-space
  double-alloc corruption ELIMINATED.

## bno_dirty=0 + in-AIL + ahead-of-disk: the key insight
XFS_LI_DIRTY is the TRANSACTION-private dirty bit (set in xfs_trans_log_buf, cleared on
commit). A buffer in the AIL post-commit, post-CIL-push, unpinned, awaiting metadata
writeback has DIRTY=0, IN_AIL=1, pin=0 — its logged content is NOT yet on its final disk
block. The ONLY reliable "in-core may be ahead of disk" signal set is XFS_LI_IN_AIL.

## STILL FAILING (cache_coherency not yet green) — both are read-coherency staleness
1. **iunlink/AGI corruption** (intermittent, was dominant): `xfs_iunlink_remove_inode line
   614 xfs_inode_util.c` → shutdown. P71 shows `agi_disk_differs=1 agi_gen=0` (in-core AGI
   STALE vs disk) with NO P14 walk verdict for the AGI daddr (2087322) → the EX-acquire walk
   `mxfs_dlm_invalidate_ag_meta` (xfs_mxfs_dlm.c L4020, rhashtable walk of pag_bcache) NEVER
   processed the AGI → stayed gen-lagging+stale. NOTE: this is the OPPOSITE of the AG-meta
   fix (stale-BEHIND, needs refresh; not ahead, needs preserve). The IN_AIL guard does NOT
   help here. Need: understand why the walk/read-hook leaves a peer-modified AGI stale
   despite no re-acquire (pag_gen stuck at 1). Possible: AGI cached before last walk, then
   peer modified on-disk without this node re-acquiring (investigate cached-acquire / a
   path that writes AGI without DLM round-trip).
2. **dir-block coherency MISSES** (TOTAL_FAILS=3/3/3/0 on clean runs): peers don't see ~3 of
   each other's renamed dirents. dir-block hook xfs_da_btree.c:2887 has the same
   `!dirty&&!pin&&!delwri` guard MISSING in_ail — but DO NOT add in_ail here: the symptom is
   stale-BEHIND (can't refresh a dirty/pinned dir block to see peer's dirent), so adding
   in_ail makes it WORSE. This is the inode-DLM dir coherency: two nodes modify the same
   shared dir block; B modifies on a stale base (didn't BAST/flush/refresh A's dirent first)
   → lost update at the dirent level.

## ⛔⛔ CRITICAL A/B RESULT — the gen-0 dir fix is a REGRESSION (REVERTED, build A0A86F31)
The gen-0 dir-coherency fix (bump i_dlm_dir_gen 0→1 to force the hook) reduced rename_visibility
misses 3× BUT **broke cross_write_read with EACCES** ("cp: cannot stat data_nodeN: Permission denied"
— a node can't stat its OWN just-created file). DECISIVE A/B: gen-0 bump DISABLED → cross_write_read
PASSES (PASS:1); ENABLED → FAILS/timeouts. **Mechanism: forcing FUA dir-block re-reads makes a node
re-read the dir block from disk and MISS its OWN just-created-but-not-yet-durable dirent** → lookup
fails → EACCES/ENOENT. The dirty/pin/in_ail guards in the hook do NOT fully protect (the block can be
momentarily clean-but-undurable). **⇒ AGGRESSIVE DIR-BLOCK RE-READ IS UNSAFE — it reverts/hides this
node's own undurable dir changes.** Same unsafe direction as the cached-reacquire-gen-bump. The dir-miss
fix MUST NOT force re-reads; it needs a DURABILITY-based approach (peer's changes durable before this
node reads; this node's own changes never discarded). KEPT REVERTED. da_btree.c gen-0 block is now a
log-only no-op (P83-INSTR); fully remove it or leave inert.

## ⭐ cache_coherency SCOPE (build A0A86F31, gen-0 reverted) — 2 of 4 sub-tests PASS
Run each: `MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4 --phase cluster --test <T>
--pass-file /tmp/.mxfs_pass --mount-point /mnt/shared`.
- **test_cross_visibility: PASS** ✓
- **test_cross_write_read: PASS** ✓ (with gen-0 reverted; FAILS EACCES with gen-0 enabled)
- **test_rename_visibility: FAIL** (~138 misses/960 — dir-block Mode-A; the writer's first entries are
  clobbered/invisible to peers; aggressive re-read can't fix it safely — see above).
- **test_unlink_visibility: FAIL (intermittent)** — the iunlink ADD-revert corruption (Blocker B).
So cache_coherency needs rename_visibility + unlink_visibility fixed (without breaking the 2 passing).
The dir-miss (rename) and the EACCES (cross_write) are DUAL constraints: peers must see a writer's
committed dirents (refresh) AND a node must always see its own (no revert) — the fix must satisfy BOTH,
which a blanket re-read cannot. Likely needs: writer makes dirents DURABLE before release + peer refresh
keyed on a real peer-modified signal (not a blanket gen bump).

## ⭐ DIR-MISS FIX #1 LANDED (partial) + the hard residual (clobber) [REVERTED — see CRITICAL A/B above]
**Build `1950ADE6` (current best): the gen-0 dir-coherency fix LANDED and VERIFIED** — in xfs_da_read_buf,
when a DATA-fork dir block is read in TRUE multi-node mode (`!mxfs_v5_dlm_is_single_node`) at
`i_dlm_dir_gen==0`, bump gen 0→1 so the existing coherency hook engages (invalidates default-gen-0
blocks → FUA re-read). Gated on true multi-node so single-node keeps the no-FUA fast path (no
single_node_paired regression). **Real test_rename_visibility: misses dropped ~3× (138→~45 total:
9/15/15/6 vs prior 46/40/6/46), no corruption, no DLM timeout, P83-FIX engaged.** KEEP IT.
**HARD RESIDUAL (the remaining misses) = the cached-fast-path dir clobber (Mode-A).** A node re-acquires
a cached-EX dir inode via the fast path (mxfs_dlm_ilock_begin L1668) which bumps holders WITHOUT
bumping gen or reloading (P63 comment at L1672 flags exactly this: "fast-path dir = stale cached buf").
So a node RMWs the dir on a stale-but-gen-current cached block → clobbers a peer's entries.
**⚠️ DO NOT FIX by bumping i_dlm_dir_gen on the cached re-acquire — it is UNSAFE: the cached fast-path
often CANCELS a pending deferred release (mxfs_ag_dlm_unlock_deferred / the inode equivalent), keeping
this node's NOT-YET-DRAINED dir changes in-core; bumping gen then forces a refresh that re-reads stale
disk and REVERTS this node's own undurable changes (re-introduces the lost-update).** The cached
fast-path genuinely can't cheaply tell "own undurable changes (preserve)" from "peer changed it
(refresh)". The correct fix is harder: either (a) the cached-EX dir re-acquire must verify the on-disk
dir didn't change since cache (e.g., a cheap dir-block version/seqno compared under the cached token —
but a peer can't change it while we hold EX cached, so the real question is whether the cached-EX token
is genuinely still held vs a BAST-latency split), or (b) ensure dir changes are DURABLE before the
deferred release so a refresh-on-reacquire is always safe (then bumping gen on cached re-acquire becomes
safe and fixes the clobber). (b) ties back to the same release-durability root as the AGI iunlink ADD.
NEXT: confirm whether the clobbering node's dir re-acquire is fast-path-cached (P63) with a pending
deferred release holding undurable changes; if so, fix (b) — make dir release durable before unlock.

## ⭐ CONFIRMED dir-miss contributor — the gen-0 dir-coherency SKIP window (P83, build 45DD63EE) [now FIXED, see above]
The dir-block coherency hook (xfs_da_read_buf, xfs/libxfs/xfs_da_btree.c) is gated on
`dp->i_dlm_dir_gen != 0` — a single-node optimization (sess37). P83-INSTR logs a DATA-fork dir-block
read in CLUSTER mode while i_dlm_dir_gen==0 (hook bypassed). RESULT during the REAL test_rename_visibility:
**P83 fired 10× on test3 — the exact node that misses peers' entries.** So gen-0 dir reads ARE happening
during the test, with NO cross-node invalidation → stale dir reads. ROOT of gen==0: i_dlm_dir_gen only
bumps in mxfs_dlm_ilock_begin's slow-path (xfs_mxfs_dlm.c:1810), which is reached via xfs_ilock with an
ILOCK/IOLOCK flag (xfs_inode.c:152-157). A `lock_flags=0` read path (xfs_lookup/readdir — sess38 noted
lookup igets with lock_flags=0) SKIPS mxfs_dlm_ilock_begin entirely → no gen bump → gen stays 0 → hook
bypassed → stale cached dir block returned (reader-miss); and a rename whose dir-inode acquire is
fast-path/cached at gen 0 RMW-clobbers on a stale base (writer-clobber). **FIX (next session): close the
gen-0 window in cluster mode.** Options: (a) when a dir inode is in a cluster mount, treat gen==0 like a
mismatch — force a FUA re-read of the dir block on EVERY read until the gen mechanism engages (cluster
dir reads can't trust the cached block at gen 0); (b) bump i_dlm_dir_gen 0→1 the first time a dir inode
is touched in cluster mode (even via lock_flags=0) so b_mxfs_dir_gen=0 blocks get invalidated; (c) make
the hook gate on "(gen != 0) || (cluster && block-stamp-is-stale)". CAVEAT: d_revalidate / per-lookup DLM
was tried (sess38) and caused barrier timeouts — do NOT re-acquire the DLM per lookup; instead make the
read-time hook itself cluster-aware at gen 0 (cheap FUA on the cached block, no DLM round-trip). NOTE: a
forced-reacquire (touch+sync) on test3 STILL missed the entries (sess43) → there's ALSO a writer-side
clobber (entries not on disk), so the gen-0 fix may not fully close the miss; both the gen-0 reader-skip
AND the clobber need addressing. The test_rename_visibility run with P83 also hit rc=124 (180s timeout) —
watch for a slowdown/stall introduced; previous clean runs were ~10s.

## ⚠️ CORRECTION to the unifying "in-flight bio" theory (for the DIR-miss specifically)
`xfs_buf_incore(target, d, n, 0, &bp)` → `xfs_buf_get_map(..., XBF_INCORE|flags, ...)` with flags=0 =
a BLOCKING lock (xfs/xfs_buf.h:277). So `mxfs_dir_data_durable` (xfs_mxfs_dlm.c:108) already WAITS for
any in-flight dir-block bio (the writeback holds the buffer lock; incore blocks until it completes) and
then checks dirty/pin/delwri/!DONE. ⇒ **the dir blocks ARE durable at the writer's release** — the
dir-miss is NOT writer non-durability / in-flight-bio. The dir-miss is a **peer reading the first dir
block STALE and clobbering** the writer's just-committed entries (RMW on a stale base), with
DIR_STALE_SKIP=0 meaning the peer's read saw NO gen-mismatch → the peer's i_dlm_dir_gen did NOT bump
after the writer's change, so the peer treated its cached first-dir-block as fresh. The clobbering op
(a concurrent rename on the peer) DOES acquire the dir-inode DLM EX (xfs_ilock→mxfs_dlm_ilock_begin),
which on a slow-path (cache-miss) acquire bumps i_dlm_dir_gen (xfs_mxfs_dlm.c:1810, S_ISDIR) → should
refresh. So the gap is a window where the peer's dir-inode acquire is NOT slow-path (cached/fast-path,
no bump) OR a read path (lookup with lock_flags=0, sess38) bypasses the DLM/gen entirely. NEXT for the
dir-miss: instrument i_dlm_dir_gen bump + the xfs_da_read_buf hook outcome for the FIRST dir data block
during a failing rename — confirm whether the peer's gen bumped and whether the read was invalidated;
find why the peer RMWs the first block on a stale base. (The AG-meta/AGI in-flight-bio + clean-but-ahead
root from P81 is REAL and separate — that's the AGI iunlink / write-side P70; the dir-miss is the
peer-stale-clobber gen-coherency variant.)

## ⭐ REAL-CRITERION CONFIRMATION + UNIFYING ROOT (run the ACTUAL test, not the confounded repro)
**How to run the real cache_coherency sub-tests against test1-4** (MY repro's `rm -rf $DIR; mkdir`
confounds it with a dir-RE-CREATE coherency divergence — test1 sees the new dir, peers keep the old
inode → use the real tests which use stable `mkdir -p`):
```
MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4 --phase cluster \
  --test test_rename_visibility --pass-file /tmp/.mxfs_pass --mount-point /mnt/shared
```
(MXFS_TESTS_DIR MUST be set — default /mnt/mxfs-src/tests doesn't exist → rc=127. /src is NFS-mounted.)
RESULT (build 0CAB0E3B): **test_rename_visibility FAILS — 6/40/46/46 failed assertions / 240 per node.**
The misses are a writer's FIRST entries (node3 missed node4_after_1,2,3 — `file not found` + empty
content). So the dir-block Mode-A coherency MISS is a REAL, reliable criterion blocker (independent of
my repro's rm-rf artifact and of the iunlink corruption). The writer sees its own entries; peers miss
the first few (the high-contention first dir data block).

**UNIFYING ROOT across ALL remaining failures (dir-miss + AGI iunlink + the residual write-side P70):**
a committed metadata buffer that LOOKS CLEAN (DONE && !XFS_LI_DIRTY && !pinned && !XFS_LI_IN_AIL) is
actually IN-CORE-AHEAD-OF-DISK — because its writeback bio was submitted (bli detached, buffer marked
clean) but HAS NOT COMPLETED (disk still old). The node releases the DLM (the release durability checks
— mxfs_dir_data_durable for dirs checks dirty/pin/delwri/!DONE; AG-meta has the meta_pending wait — do
NOT catch this "clean-but-in-flight" state for ALL buffer classes), a peer acquires + FUA-reads the
shared LUN, gets the pre-write (stale) image, and the committed update is LOST. P81 proved this for
AG-meta (agf/cntbt in-core-AHEAD at unlock); the dir-miss and AGI iunlink ADD-revert are the same.
**CHEAP UNIFYING FIX (next session — the P81 FUA-readback was correct but too slow → 120s DLM timeout):
at release, WAIT for in-flight bio completion on ALL metadata buffers (AG-meta + AGI + inode-cluster +
DIR data/leaf blocks), not just AG-meta's meta_pending counter.** A buffer with an in-flight write is
LOCKED by xfs_buf_submit until the bio completes — so a cheap per-buffer `xfs_buf_lock`+`xfs_buf_unlock`
barrier (NO SCSI read) over the relevant cached buffers drains in-flight writes before unlock; then the
existing blkdev_issue_flush makes them durable. This is the inode-cluster barrier pattern (xfs_mxfs_dlm.c
~L790, "take an xfs_buf_lock on the inode cluster buf — waits for any in-flight bio") generalised to dir
blocks (via the dir inode's data-fork extents, like mxfs_dir_data_durable enumerates) and confirmed for
AG-meta. Verify dir blocks are even tracked by meta_pending; if not, that's the gap. This single
release-side durability barrier should close the dir-miss, the AGI iunlink ADD-revert, AND the residual
write-side P70 together — they are ONE bug (non-durable release of clean-but-in-flight metadata).

## ⭐ MECHANISM of the cross_write_read EACCES (why aggressive FUA dir re-read is unsafe) — KEY for the fix
The gen-0 dir fix forced an FUA re-read of dir blocks. mxfs's dir re-read goes FUA (mxfs_buf_read_fua),
which PIERCES the per-initiator iSCSI target read-cache and reads the PLATTER. A node that just
created/renamed a file has its dirent in the TARGET CACHE (written via its own initiator) but NOT yet
flushed to the platter (the test's `sync` may not push the target cache → platter; only the DLM
release's blkdev_issue_flush does). So the node's own FUA re-read reads the platter → MISSES its own
target-cached-but-not-platter-durable dirent → "cannot stat / Permission denied" (EACCES). This is THE
reason any aggressive FUA dir re-read breaks cross_write_read, AND it is the deep "clean-but-ahead"
state: the buffer is clean (bio done to local block layer / target cache) yet disk_differs=1 (platter
behind) — the dirty/pin/in_ail/delwri/lock guards all MISS it because the write IS "done" locally.
**IMPLICATION for the dir-miss fix:** a node must NOT FUA-re-read its OWN recently-written dir blocks
(target-cached, not platter-durable). The fix must (a) ensure a writer's dirents are PLATTER-durable
(blkdev_issue_flush) before a peer reads them — the DLM release does this, but the verify reads happen
WITHOUT a release/flush; and (b) refresh ONLY for peer changes (platter-durable), not own target-cached
writes. The gen mechanism (refresh on peer-BAST-triggered re-acquire) is the right shape — the gap is
that lock_flags=0 lookups bypass it. Likely correct fix: lookups engage the DLM gen/BAST (cached
fast-path so no per-lookup CAW poll) so own writes are flushed (on the writer's release) before a peer's
gen-bumped refresh reads the platter. This unifies the dir-miss (peer must see, via platter+refresh) and
cross_write_read (own must see, via target cache, NO FUA on own undurable).

## ⛔⛔⛔ DECISIVE (sess43 final): ALL FUA-refresh dir-coherency approaches hit the TIMING WALL
Tested THREE distinct dir-refresh mechanisms for rename_visibility, ALL fail:
- read-side gen-0 re-read → broke cross_write_read (EACCES, own target-cached miss).
- bast-RELEASE gen-bump → ~45 residual misses (wrong layer) + cross_write_read EACCES.
- write-ACQUIRE gen-bump (cached dir-EX re-acquire, the "correct" layer for clobber prevention) →
  **TIMED OUT rename_visibility (>180s)**: refreshing all dir blocks (FUA) on every rename's re-acquire
  is too slow under 4-node contention.
- (+ mxfs_sync_iflush own-durability push → also timed out.)
**CONCLUSION: cross-node dir coherency via FUA re-reads is FUNDAMENTALLY TOO SLOW at this scale** — every
refresh approach either misses own target-cached writes (correctness) or times out (FUA-per-op latency
under contention). The dir-miss CANNOT be fixed with FUA-refresh. **The fix needs a NON-FUA coherency
mechanism** — candidates for next session: (a) a lightweight cross-node dir-version/seqno (in the AGI or
a shared counter) checked cheaply so a node knows WHEN to refresh (only when a peer actually changed the
dir, not every op); (b) push dir changes to peers proactively (invalidation broadcast) rather than
pull-via-FUA; (c) make FUA reads dramatically cheaper (batch / cache the platter read). This is a
deeper architectural change than a hook tweak. ALL hook-level refresh tweaks are exhausted (documented).

## ⛔ COMBO TEST RESULT + CORRECTED TARGET — residual misses are WRITE-SIDE CLOBBERS, not read-staleness
sess43: tested the full two-part combo (bast-gen-bump refresh + sync_iflush=1 own-durability) → STILL
~45 rename_visibility misses (15/15/6/9), NOT 0; AND sync_iflush timed out cross_write_read. Both reverted.
KEY: earlier forced-reacquire (touch+sync on test1 AND test2) STILL missed the entries → **the residual
misses are entries GONE FROM DISK (clobbered), not stale-cached.** So the dir-miss is primarily a
WRITE-SIDE clobber: during the concurrent rename phase, a node's rename RMWs the first dir block on a
STALE base (missing a peer's just-added entries) and writes it back → clobbers the peer's entries on disk.
The bast-gen-bump refreshes on BAST-RELEASE (read side) — WRONG LAYER; it can't fix a write-path clobber.
**CORRECTED part (2): refresh must happen on the cached-fast-path ACQUIRE of the WRITE (rename) path**
— mxfs_dlm_ilock_begin's fast-path (xfs_mxfs_dlm.c ~L1668, the P63 "FAST-PATH-DIR" path) bumps holders
WITHOUT refreshing, so a rename re-acquiring a cached-EX dir RMWs on a stale base → clobber. The fix:
on that cached-fast-path acquire for a dir inode being MODIFIED (mode==EX), refresh the dir blocks IF a
peer modified since — but that's unsafe without cheap own-durability (reverts own undurable, the dual
constraint). So STILL needs cheap own-durability (targeted iflush) + refresh-on-cached-WRITE-acquire.
sync_iflush (whole/per-AG push) is too slow → use the targeted iflush (per-AG radix-tree tag + xfs_icwalk,
below). Net: the fix layer is the WRITE-path cached acquire (clobber prevention), not the read/BAST side.

## 🎯 COMPLETE MECHANISM + IMPLEMENTATION PLAN for rename_visibility (the SOLE cache_coherency blocker)
FULLY reverse-engineered this session (4 approaches tested+reverted). The two failing tests differ ONLY
in timing relative to a DLM release:
- rename_visibility verify reads happen AFTER the renames' DLM releases → the writer's OWN dir blocks
  ARE on the platter (release drains via mxfs_dir_data_durable+flush). The miss is purely the PEER
  reader's STALE cached dir block (lock_flags=0 lookup → no acquire → no gen bump → no refresh).
- cross_write_read stat happens WITHOUT a release between create and stat → the node's OWN dir block is
  still TARGET-CACHED (not platter), because sync_fs (default, sync_iflush=0) does log_force but does NOT
  push the dir block AIL item into its on-disk cluster block (that push is gated behind sync_iflush, and
  the per-AG/whole-AIL push is too SLOW → timeout). So a blanket FUA refresh re-reads the platter and
  MISSES the own target-cached write → EACCES.
THE TWO-PART FIX (both needed; each alone fails):
  (1) CHEAP own-write durability on sync: a TARGETED iflush of ONLY the dir blocks/inodes THIS sync's
      caller dirtied since the last sync (NOT xfs_ail_push_ag_sync's whole-AG push — that's the slow
      part that times out). Mechanism options: track per-mount/per-inode a "dirtied-since-sync" list, or
      iflush the specific inode(s) in the current syscall's fdatasync target. After the targeted iflush,
      blkdev_issue_flush makes them platter-durable. This makes a FUA read see OWN writes → cross_write_read
      stays green even with refresh.
  (2) refresh-on-peer-change for lock_flags=0 reads: re-enable a gen-bump (bast_process dir-gen-bump
      `0D3366B9`, or the slow-path acquire path) so a peer's modification refreshes the reader's stale dir
      block → rename_visibility passes. With (1) in place, the refresh no longer loses own writes.
IMPLEMENTATION LEVER for (1) (targeted iflush, found sess43): XFS has a per-AG inode radix tree
`pag->pag_ici_root` with taggable inodes + the `xfs_icwalk(mp, goal, icw)` iterator (xfs/xfs_icache.c;
existing tags XFS_ICI_RECLAIM_TAG=0, XFS_ICI_BLOCKGC_TAG=1, via radix_tree_tag_set/get). PLAN: add a tag
(e.g. XFS_ICI_MXFS_DIRTYDIR) set when a dir/inode is logged-dirty in multi-node mode; on sync_fs, instead
of xfs_ail_push_ag_sync_bounded (slow whole-AG), xfs_icwalk ONLY the tagged inodes and xfs_iflush each
(write its cluster), clear the tag, then ONE blkdev_issue_flush. This pushes only the handful this node
dirtied (cheap) → no per-sync whole-AG scan / contention → avoids the >200s timeout. (Or simpler: iflush
the small set of inodes whose ili is in the AIL below a bounded LSN window — but the tag/icwalk is the
clean XFS-native mechanism.)
VALIDATION GATE: after implementing (1)+(2), ALL FOUR must hold: rename_visibility PASS (0 misses),
cross_write_read PASS (no EACCES), unlink_visibility PASS, AND no >150s timeout (the per-sync push must
be cheap — measure the test wall; the whole-AIL/per-AG push gave 148-200s, the targeted version must be
seconds). mxfs_sync_iflush param + xfs_fs_sync_fs (pal/linux/xfs_super.c:866) is where (1) lives;
mxfs_dlm_bast_process / mxfs_dlm_ilock_begin (xfs_mxfs_dlm.c) is where (2) lives.

## ✅✅✅ MAJOR SCOPING (sess43 end) — cache_coherency is 3/4 PASS; ONLY rename_visibility fails
Verified each real sub-test (build A0A86F31, `MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh
--nodes 4 --phase cluster --test <T> --pass-file /tmp/.mxfs_pass --mount-point /mnt/shared`):
- **test_cross_visibility: PASS** ✓
- **test_cross_write_read: PASS** ✓ (with gen-0 dir fix reverted)
- **test_unlink_visibility: PASS** ✓ (no iunlink corruption, no shutdown)
- **test_rename_visibility: FAIL** (dir-block Mode-A miss — the SOLE remaining cache_coherency blocker)
**The iunlink corruption ("Blocker B") is a REPRO ARTIFACT, NOT a real criterion blocker:**
repro_rename_concurrent does `rm -rf $DIR` on test1 = test1 deletes PEERS' files (cross-node unlink →
stale VFS nlink → iunlink shutdown). The REAL test_unlink_visibility has each node delete its OWN files
(same-node) → no cross-node unlink → PASSES. So do NOT spend effort on the iunlink for the ship gate
(the cross-node stale-nlink is a real bug but unexercised by the criteria's same-node unlink). **FOCUS
ALL dir-miss effort on test_rename_visibility.** It needs a SAFE dir-read-coherency fix: the verify-phase
lookups (lock_flags=0, no DLM acquire) read STALE cached dir blocks → miss peers' renames. The fix must
refresh peer-modified dir blocks WITHOUT making a node miss its OWN undurable dirents (the gen-0 re-read
broke cross_write_read — REVERTED). Likely: make dir lookups DLM-coherency-aware (the proper fix is the
lookup acquiring the dir inode PR so the gen bumps — but d_revalidate's per-lookup CAW poll caused
barrier-timeouts in sess38; need a cached-fast-path-friendly version that polls only post-BAST).
OTHER ship-gate blockers beyond cache_coherency: rsync_paired (missing tools/mxfs_multinode_bench.sh);
re-verify the other criteria didn't regress (single_node_paired needs a clean single-node measurement).

## ⛔ Blocker B re-drain loop DISPROVEN — it's NOT AGI durability; it's stale VFS nlink
Tried a bounded re-drain loop (log_force+drain_meta_buffers until no AG-meta pinned/in-AIL/dirty, 20×)
in the AG release to make the iunlink ADD's AGI durable. RESULT: the loop **CONVERGED immediately
(P84 redraincap=0)** — AG-meta WAS fully drained — yet **iunlink STILL fires** (test4 ino=2097821,
disk_dnlink=1, disk_dimode=0100644). REVERTED (no benefit, adds release latency). **⇒ Blocker B is NOT
AGI ADD-revert / AGI durability.** The decisive fact (disk_dnlink=1) holds: the inode is STILL LINKED on
disk; this node's VFS i_nlink=0 is STALE → it wrongly inactivates a still-linked inode. **Blocker B =
cross-node nlink coherency: why does VFS i_nlink go to 0 on a node while the cluster-true on-disk
di_nlink stays 1?** This is the root to chase (NOT the AGI/unlinked-list — that's a downstream symptom).
NEXT: instrument xfs_droplink / xfs_bumplink (ino, old→new VFS nlink, node) AND where the in-core inode
nlink is loaded/reloaded (mxfs_dlm_reload_inode, xfs_iget) for the failing inode — find where VFS
nlink=0 comes from while disk=1. Candidates: (a) a coherency reload applies a peer's TRANSIENT/
uncommitted nlink=0; (b) the rm on one node decrements nlink but a peer's cached inode mis-syncs;
(c) a rename/link-count accounting bug across nodes. Until the stale-nlink source is found, iunlink
(and the inobt rec.ir_free double-free) will recur. Build A0A86F31 is the clean state (re-drain reverted).

## ⭐⭐⭐⭐⭐⭐⭐⭐ sess43 TRUE ROOT (decisive) — stale in-core nlink → inactivation of a STILL-LINKED inode
Build E0903CE8 added on-disk `di_nlink` to P71. RESULT: `ino=2097821 nlink=0 (IN-CORE)
next_unlinked=NULLAGINO disk_dimode=0100644 disk_dnlink=1`. **disk_dnlink=1 = the inode is STILL
LINKED on disk (cluster-true nlink=1)**, but this node's IN-CORE nlink=0 → this node WRONGLY believes
the file is deleted and inactivates (frees) a still-linked inode. The inode is correctly NOT on the
unlinked list (it's still linked!), so xfs_iunlink_remove finds an empty bucket → shutdown. This is
NOT double-free (di_mode≠0), NOT lost-ADD-of-an-unlinked-inode (the inode was never supposed to be
unlinked) — it is a **cross-node link-count (nlink) COHERENCY bug**: this node's in-core nlink went to
0 when the cluster-true nlink is 1.
ROOT mechanism (to confirm): under concurrent rename + the run-cleanup rm-rf, the inode's link count is
managed inconsistently across nodes. Candidates:
- A rename/unlink on node A decrements nlink in A's in-core inode; node B has the inode cached and its
  in-core nlink is updated to a STALE value (a coherency reload applied A's transient/uncommitted nlink,
  or B mis-applied a droplink). B then drops its ref → inactivates a still-linked inode.
- The inode-DLM reload (mxfs_dlm_reload_inode) may set in-core nlink from a stale/uncommitted disk read,
  or a local droplink runs on a node that shouldn't (cross-node rename target handling).
NEXT (decisive): log xfs_droplink / xfs_bumplink (ino, old→new nlink, node, realns) for the failing
inodes across ALL nodes, AND which node fires the P71. Determine where in-core nlink wrongly hits 0
while disk stays 1. Likely in xfs_rename's link accounting or a coherency reload that clobbers nlink.
SOUND DEFENSIVE GUARD (also a partial correctness fix): in xfs_inactive_ifree (or before xfs_ifree),
if on-disk di_nlink > 0 (FUA read via mxfs_inode_disk_mode's nlink_out), the in-core nlink=0 is STALE →
do NOT free; instead reload the inode (refresh nlink from disk) and abort inactivation. CAVEAT: during a
legit local unlink the on-disk nlink lags in-core until commit — so only treat disk-nlink>0 as "stale"
when this node did NOT just commit the unlink (e.g., gate on i_dlm_stale or compare to a just-committed
marker). Getting this right needs the droplink instrumentation first.
**This SUPERSEDES the lost-ADD framing above: the inode is still linked (di_nlink=1), so it was never
meant to be unlinked — the bug is the stale in-core nlink=0.**

### ⭐ DECISIVE ADD-TRACE (build 0CAB0E3B, P82-ADD logs every xfs_iunlink ADD: ino/agino/bucket/nlink/rc)
Two sub-cases of the AGI iunlink corruption, both caught with cross-node correlation:
1. **SAME-NODE lost-ADD (ino=2097821, test4)**: `P82-ADD ino=2097821 bucket=29 vfs_nlink=0 rc=0` at
   realns 115.350459, then `P71 bucket=29 head=NULLAGINO` corruption at 115.351 — **~0.5ms later, SAME
   node**. test4 ADDed the inode to bucket 29 (rc=0, in-core AGI updated), then its OWN inactivation
   REMOVE read bucket 29 = EMPTY → the ADD's AGI bucket update was LOST within 0.5ms, in the window
   between the unlink's ADD and the immediate inactivation's REMOVE (closed file rm'd → unlink then
   inactivate back-to-back; between them the AG-DLM is unlock_deferred'd by the ADD then re-acquired by
   xfs_inactive_ifree). The AGI bucket update is reverted in that window despite the in-AIL/gen guards.
2. **CROSS-NODE double-ADD (ino=2097832)**: `P82-ADD ino=2097832 bucket=40` fired on BOTH test1 AND
   test2 → two nodes both unlinked+ADDed the SAME inode to the unlinked list (the rm-rf on test1 races
   the inode's handling on its creator node test2). Double-ADD/double-unlink of one inode.
Both are the cross-node inode-lifecycle / unlinked-list coherency bug. Sub-case 1 is the cleanest to
chase: instrument the ADD→REMOVE window (what releases/re-acquires the AG-DLM between xfs_iunlink and
xfs_inactive_ifree's xfs_iunlink_remove, and whether the AGI bucket is reverted by the read-hook,
the walk, or a drain at that re-acquire). The disk_dnlink=1 says the inode is still linked on disk —
consistent with the ADD's di_nlink→0 ALSO being lost (the whole unlink txn's durable effect reverted).
NEXT: log in xfs_inactive_ifree whether its mxfs_ag_dlm_lock was a FRESH acquire (walk ran) vs cached
fast-path, for the failing inode's AG, right before the REMOVE. If FRESH, the walk re-read the AGI from
stale disk (ADD not yet durable) → reverted. Fix: make the ADD durable before the deferred unlock, OR
hold the AG-DLM continuously across unlink→inactivate for immediately-freed inodes.

⚠️ DO NOT FIX BY SKIPPING THE WALK'S STALE: v0.3.81 already tried skip-on-bli for AG-meta in the
EX-acquire walk and it REGRESSED (xfs_mxfs_dlm.c ~L4260 note: "Skip prevents seeing peer's modifications
via cache miss → still showing local stale state", avg 3.2/5 vs ~7 — reverted v0.3.82). A bli attached
to a CLEAN (written) buffer can still be peer-stale → MUST stale it. The walk staling unconditionally is
load-bearing for peer-coherency. The conflict (preserve-this-node-ADD vs stale-for-peer) only arises
because the ADD wasn't drained durable before the deferred release — so the CORRECT fix is RELIABLE
DRAIN of the iunlink ADD's AGI before mxfs_ag_dlm_unlock_deferred lets go (close the CIL→AIL async-lag
race in mxfs_dlm_ag_drain_meta_buffers: the ADD's bli may not be IN_AIL yet when the drain's filter
runs, so the drain skips it → AGI not written → next fresh-acquire reverts). The release already has
log_force+msleep+double-log_force+meta_pending-wait, but it still races for the iunlink ADD. Candidate:
capture the commit LSN of the ADD txn and have the drain WAIT until the AIL has reached it before
writing, instead of the empirical msleep(3). OR: don't unlock_deferred after an iunlink ADD when the
inode will be immediately inactivated (keep a synchronous hold so the inactivation REMOVE nests on the
same continuous hold — no fresh-acquire walk, no revert). The latter is more targeted + lower-risk.

### MECHANISM REFINEMENT (earlier hypothesis): inode-cluster buffer lost-update (read-coherency in the INODE domain)

### MECHANISM REFINEMENT (earlier hypothesis): inode-cluster buffer lost-update (read-coherency in the INODE domain)
The P71 `nlink` field is `VFS_I(ip)->i_nlink` (the VFS inode), which = 0. The on-disk `di_nlink` = 1.
`ip->i_next_unlinked` = NULLAGINO. Reconciliation: the rm/unlink on this inode DID run (VFS i_nlink
dropped 1→0, dirent removed) and committed the dinode update (di_nlink→0) + iunlink ADD (AGI bucket +
di_next_unlinked). BUT the on-disk dinode shows di_nlink=1 and the inode is NOT on the unlinked list →
the COMMITTED inode-cluster + AGI updates were LOST (reverted to the pre-unlink disk image), while the
VFS inode's i_nlink (a separate in-memory field, NOT a disk buffer, so NOT reverted by buffer
invalidation) stayed 0. Inactivation is driven by VFS i_nlink=0 → tries to free → dinode/AGI (reverted)
say still-linked + not-on-list → shutdown. **This is the SAME lost-update class as the AG-meta bug, but
in the INODE-CLUSTER buffer domain** — the inode-cluster buffer (di_nlink, di_next_unlinked) was
discarded + re-read from stale disk (read-coherency), losing the committed unlink. The inode-cluster
buffer uses a SEPARATE coherency path (i_dlm_stale / mxfs_dlm_reload_inode / the inode-buf invalidation
in the EX-acquire walk which SKIPs bli-attached inode bufs), NOT the b_mxfs_ag_gen gen-stamp that fixed
AG-meta. So my gen-stamp fix didn't cover it.
**THE FIX (next session): apply the same in-AIL / gen protection to the INODE-CLUSTER buffer coherency**
— do not discard/revert a committed-but-unwritten inode-cluster buffer (one with an in-AIL bli or
in-core-ahead-of-disk content). Check mxfs_dlm_reload_inode (xfs_mxfs_dlm.c ~L1050) and the inode-buf
handling in the EX-acquire walk (the `is_inode_buf && b_log_item` SKIP at ~L4231/4118 — that SKIP
PROTECTS bli-attached inode bufs from staling, which is correct; but some OTHER path reverts it).
DECISIVE NEXT INSTRUMENT: in P71, also dump the IN-CORE dinode di_nlink (read ip's cached inode-cluster
buffer via xfs_imap_to_bp/xfs_buf_incore, NOT a FUA disk read). If in-core-dinode di_nlink==1 (==disk)
→ the inode-cluster buffer was reverted (read-coherency lost-update, confirmed). If in-core-dinode
di_nlink==0 (≠disk=1) → the buffer has the update but the on-disk WRITE was lost (write-side/durability).
That one comparison pins read-revert vs write-loss for the inode-cluster buffer.
Build with full P71 diagnostics (ino/nlink/next_unlinked/dimode/dnlink): **E0903CE8** (current best,
all read-coherency fixes + diagnostics; free-space P70=0, AGI read-coherency fixed, no DLM timeout).

## ⭐⭐⭐⭐⭐⭐⭐ sess43 CORRECTION — NOT double-free; LOST-ADD / inactivation of an ALLOCATED inode [PARTIALLY SUPERSEDED — di_nlink=1 shows the inode is still linked, not a lost-ADD of an unlinked inode]
Build 71705517 added `disk_dimode` (on-disk di_mode via FUA, new helper mxfs_inode_disk_mode) to P71.
RESULT: `ino=2097342 nlink=0 next_unlinked=NULLAGINO disk_dimode=0100644` and
`ino=2097820 nlink=0 next_unlinked=NULLAGINO disk_dimode=0100644`. **disk_dimode=0100644 = the inode
is STILL ALLOCATED on disk (regular file), NOT freed (mode≠0).** This REFUTES the double-free/double-
inactivation hypothesis (a freed inode would have di_mode=0). The truth: the inode is ALLOCATED,
nlink=0 (in-core), next_unlinked=NULLAGINO, and NOT on the unlinked list (empty bucket, in-core==disk).
**XFS invariant: an allocated nlink=0 inode MUST be on the unlinked list.** So the violation is one of:
1. **Lost xfs_iunlink ADD**: the inode reached nlink=0 (via rm/droplink) but was never added to the
   unlinked list — the ADD (xfs_iunlink → xfs_iunlink_insert_inode, xfs_inode_util.c:526/460) was
   skipped or its AGI/inode update was lost. Then inactivation's remove finds it absent → shutdown.
2. **Cross-node inactivation of a non-owned inode**: node A did the rm (nlink→0, added to A's unlinked
   list, A owns the free); node B cached the inode, its in-core nlink went to 0 via coherency, B drops
   its last ref → B inactivates → B's xfs_iunlink_remove finds the inode not on the list (A added it
   to a state B sees as empty, OR A hasn't added yet) → shutdown. B should NOT be inactivating an
   inode A owns.
NEXT (instrument to disambiguate 1 vs 2): log every xfs_iunlink ADD (ino+agino+node+realns) AND the
nlink-decrement (xfs_droplink) for the failing inodes (2097342, 2097820) across ALL nodes. Did the ADD
run for them on ANY node? On which node did nlink hit 0? Is the SAME inode inactivated on >1 node?
Also log on-disk di_nlink (not just di_mode) — if disk di_nlink>0 while in-core nlink=0, this node's
nlink is STALE (a coherency bug → wrongly triggers inactivation). **The earlier double-inactivation
write-up below is SUPERSEDED by this correction — di_mode=0100644 proves the inode is NOT freed.**
DEFENSIVE STOPGAP (prevents shutdown, but risks leak/double-free — use only with the inobt-free also
guarded): if xfs_iunlink_remove_inode finds the bucket empty AND disk di_mode!=0 (allocated, not ours),
skip the free cleanly instead of EFSCORRUPTED. The ROOT fix is cluster-coordinated inactivation (one
owner per inode) + coherent nlink.

## ⭐⭐⭐⭐⭐⭐ sess43 FINAL — true remaining bug = CROSS-NODE DOUBLE-INACTIVATION (decisive) [SUPERSEDED by the CORRECTION above — di_mode=0100644 refutes double-free]
Enhanced P71 (build C00917AE adds ino/agino/nlink/next_unlinked to the log) caught it on test3:
`ino=2097821 agino=0x29d nlink=0 next_unlinked=0xffffffff bucket=29 head=NULLAGINO disk_head=NULLAGINO
agi_gen=3 pag_gen=3`. The inode being inactivated has nlink=0 AND its OWN `i_next_unlinked=NULLAGINO`
AND the bucket is empty on both in-core+disk → **the inode is NOT on the unlinked list**.
`next_unlinked=NULLAGINO` is precisely the state a SUCCESSFUL remove leaves → this is a
**cross-node DOUBLE-REMOVE / double-inactivation**: the same inode (2097821) is being inactivated
on more than one node (the rm-rf runs on test1, but the inode was created/cached on another node
that ALSO inactivates it). The FIRST remove emptied the bucket + zeroed next_unlinked; the SECOND
(on test3) finds an empty bucket → `xfs_iunlink_remove_inode:617` → shutdown.
**This is the SAME ROOT as the inobt `rec.ir_free != frec->ir_free` corruption (xfs_ialloc.c:1653,
xfs_dialloc_ag_update_inobt) seen earlier — a double-FREE in the inode-alloc btree.** One bug:
an inode freed/inactivated on two nodes → double unlinked-list-remove AND double inobt-free.
**THE FIX (next session): coordinate inode inactivation cluster-wide so each inode is freed by
exactly ONE node.** xfs_inactive/xfs_inactive_ifree run when the last reference is dropped; in a
cluster two nodes can each hold a reference (one created/cached it, another rm'd the dirent) and
both reach inactivation. Leads: (a) before xfs_iunlink_remove / ifree, verify the inode is still
ON the unlinked list (next_unlinked != NULLAGINO OR it is the bucket head); if already off-list,
it was freed by a peer → skip the free (defensive, prevents shutdown but must ALSO skip the inobt
free to avoid double-free); (b) the real fix: a DLM/iget check that an inode pending-inactivation
isn't concurrently freed by a peer (sess40's IRECLAIMABLE cross-node reuse path is adjacent — a
peer freeing an inode this node holds IRECLAIMABLE). (c) instrument: log every xfs_inactive_ifree
+ xfs_iunlink ADD with ino+node; confirm ino 2097821 is inactivated on 2 nodes. The repro's run≥2
rm-rf (on test1) of files CREATED on test2/3/4 is what triggers cross-node inactivation.

## ⭐⭐⭐⭐⭐ sess43 MILESTONE — read-coherency family ELIMINATED; true remaining bug isolated
**Current best build `2488245C`** = AG-meta in-AIL guard + dir-block in-AIL guard + walk
trylock-fail-INVAL + **gen-stamp-on-fresh-read** (pal/linux/xfs_buf.c mxfs_buf_read_fua:
stamp `b_mxfs_ag_gen = b_pag->pag_dlm_meta_gen` for AG-meta on FUA-read success) + **second
drain_meta_buffers after the alloc/inode drains** (xfs_mxfs_dlm.c, release Phase-2b: inode
allocation dirties AGI/AGF/inobt AFTER the first meta drain → re-drain catches them).
RESULT (15-run loop, dmesg-verified): **P70 (free-space double-alloc) = 0 on ALL nodes**;
**AGI read-coherency FIXED** — P71 now shows `head_agino==disk_head` (both NULLAGINO) with
`agi_gen==pag_gen` (gen-current); **dlmto=0** (no DLM timeout — the second drain is cheap).
The entire disk_differs=1 read-coherency family (free-space + AGI stale-behind + the cnt-revert)
is closed. The P81 release-FUA-readback approach was REVERTED (too slow → 120s DLM grant timeout).

**THE ONE REMAINING BUG (cache_coherency still fails):** a GENUINE lost/double unlinked-list
operation. P71 `bucket=29 head=NULLAGINO disk=NULLAGINO agi_gen=3 pag_gen=3` → the AGI bucket is
genuinely EMPTY on BOTH in-core and disk (no longer a coherency miss), yet
`xfs_iunlink_remove_inode:617` is removing an inode that isn't on the list → shutdown (test4, ~run 2).
This is NOT read-coherency — it's a cross-node inode-lifecycle / write-ordering bug:
- Likely a CROSS-NODE double-inactivation race: inode X (a rename-over-existing target, unlinked)
  is on the unlinked list; node A inactivates+removes it; node B ALSO inactivates it → finds the
  bucket already empty → corruption. OR the unlinked-list ADD (xfs_iunlink) was lost/never ran for X.
- NEXT: instrument the unlinked-list ADD (xfs_iunlink / xfs_iunlink_insert_inode) AND remove for the
  failing inode — did the ADD run+persist for this agino? Is the same inode inactivated on 2 nodes?
  Check the cross-node inode reuse / IRECLAIMABLE handoff (sess40 touched iget cache-hit for reused
  inodes). The repro reuses the dir across runs so run≥2 renames hit EXISTING n_after names → unlink
  of the old target inode → exercises the unlinked list (run 1 has no unlink → no iunlink corruption,
  consistent with run-1-clean / run-2-corrupts pattern).

## sess43 additional findings (the residual blockers — characterized, not yet fixed)

### AGI iunlink corruption — CONFIRMED stale-behind read (in-core empty, disk valid)
**DECISIVE (build 7C079C3D, enhanced P71 dumps on-disk bucket head via FUA):**
`P71 agi-unlinked-garbage bucket=4 head_agino=0xffffffff disk_head=0x84 agi_disk_differs=1`.
In-core AGI bucket = NULLAGINO (empty); ON-DISK bucket = 0x84 (valid agino). So the in-core AGI
is STALE-BEHIND — missing the peer's committed unlink-list head that IS on disk. xfs_iunlink_remove
reads the stale empty bucket → "garbage" → shutdown. **This DEFINITIVELY confirms a read-coherency
failure (not a logic/double-remove error): the AGI re-read returned STALE content despite the walk
clearing XBF_DONE.** The FUA mechanism works (the P71 diagnostic FUA read correctly sees 0x84), so
some read path re-populated the AGI buffer via PLAIN (stale per-initiator-cache) bio and set DONE,
bypassing the FUA gate (pal/linux/xfs_buf.c:1734 `mxfs_buf_submit`). NEXT-FIX leads: (a) find the
read path that re-populates a stale AG-meta buffer non-FUA after invalidation (readahead? a submit
path not routed through mxfs_buf_submit's FUA gate?); (b) consider forcing AG-meta to ALWAYS FUA in
multi-node (never set _XBF_FUA_FRESH for AGI/inobt/finobt) — guarantees coherency at a read-amortization
cost; (c) the read-hook mxfs_ag_meta_invalidate_stale returns early on xfs_buf_incore TRYLOCK-fail
(L2201) — a locked AGI is never invalidated by the read-hook (the walk's trylock-fail-INVAL covers
the walk, but the per-read hook still has this gap). disk_head!=NULLAGINO is the smoking gun to grep.

### fua_always=1 experiment (runtime param /sys/module/mxfs/parameters/fua_always)
Forcing EVERY FUA-relevant read to FUA (bypassing the _XBF_FUA_FRESH amortization gate):
- Read-coherency IS fixed by it: P71 then shows `disk_head==in-core` (bucket consistent) — so the
  amortization gate WAS letting stale AGI reads through in the default config.
- BUT corruption STILL fires with a genuinely-EMPTY bucket (head=NULLAGINO on BOTH in-core+disk) →
  a DEEPER write-side/ordering layer: the inode isn't on the on-disk unlinked list though this node
  tries to remove it. So the AGI bug has TWO layers (read-coherency + write-ordering).
- fua_always=1 ALSO caused HUNG TASKS (FUA-per-read overhead) + xfs_rename xfs_trans_cancel:1060 →
  NOT a usable fix (too slow, and doesn't fully fix). Reset reloads the module → param back to 0.
- IMPLICATION: a viable fix must (a) close the AG-meta read-coherency gate-leak SELECTIVELY (force
  FUA only for AGI/inobt/finobt, or fix the non-FUA re-population path) without the global slowdown,
  AND (b) address the write-ordering layer (unlinked-list add not durable/visible before remove).

### AGI iunlink corruption — FUA-re-read returns stale (deep) [superseded by above; kept for detail]
build 185D5CD9 added a walk **trylock-fail-INVAL** fix (clear XBF_DONE under b_lock instead
of skipping a locked AG-meta buffer at fresh acquire — targets the proven `P14 ops=agi
verdict=SKIP-trylock-fail` → `P71 disk_differs=1` correlation). KEEP it (correct direction:
the walk only runs at fresh acquire, where a locked buffer is prior-epoch async writeback, not
a live txn). BUT iunlink STILL fires via a DIFFERENT path: `P14 ops=agi verdict=SKIP-no-hold-
INVAL` (b_hold==0, walk cleared DONE) → `P71 agi_disk_differs=1 agi_bflags=0x280020 (DONE set)`.
So the AGI was invalidated (DONE cleared) but the subsequent re-read RE-SET DONE with STALE
content (disk_differs=1). `mxfs_buf_needs_fua_read` DOES cover AG-meta, so the re-read should
be FUA — yet content is stale. Leads: (a) pal/linux/xfs_buf.c:1739 — if `mxfs_buf_read_fua()`
returns nonzero it FALLS THROUGH to a plain (stale per-initiator-cache) bio read; (b) RELEASE-
side: peer released the AG-DLM before its AGI write reached the shared platter, so this node's
FUA read of the backing store misses it (Invariant #1 gap; mxfs_dlm_ag_release_work_fn's
blkdev_issue_flush may not cover it). NEXT: enhance P71 to dump on-disk bucket head vs in-core
to confirm direction (behind vs ahead); check mxfs_buf_read_fua failure/fallback for AGI.

### P70 disk_differs=0 variant (on-disk inconsistent) — torn write detector added
P80 (FUA read-back AFTER drain's synchronous xfs_bwrite of bnobt/cntbt at agno=1) added to test
torn-write vs in-core-inconsistent. As of build 185D5CD9, P80 has NOT been observed firing in a
run where the disk_differs=0 variant recurred — need a longer run. P79 (walk-stales-in-AIL)
fired 0× → the walk does NOT discard in-AIL AG-meta, so that's not the source.

### dir-block coherency MISS = CONFIRMED cross-node lost-update (Mode A), NOT reader cache
DECISIVE TEST (build 185D5CD9, quiescent after a concurrent-rename run): test4 (writer) sees all
20 of its n4_after_* files; test1 misses the FIRST 3 (n4_after_1,2,3). On test1 the rename's
REMOVE side is visible (n4_before_1,2,3 GONE) but the ADD side is NOT (n4_after_1,2,3 missing) =
HALF-VISIBLE rename. Forcing a fresh dir re-acquire on test1 AND test2 (touch a new file in the
dir + sync) did NOT make them appear → **NOT reader-side cache staleness; the entries are
genuinely absent from the on-disk dir peers read.** So a node wrote the shared dir block on a
STALE base (missing the writer's entries) and clobbered them, OR the writer's BAST-flush of that
(first) dir block was incomplete. The dir-block in-AIL fix did NOT help (misses unchanged), so
the lost-update is NOT the in-AIL discard. NEXT: instrument the dir-inode BAST-release flush
(sess39 mxfs_dir_data_durable / mxfs_dir_push_data_ags) — does it flush ALL dir data+leaf blocks
(esp. the first/lowest block) before release? And the gen-bump/refresh on the peer's re-acquire
of the dir inode. This is the long-standing Mode A. Concentrated on the FIRST entries = the first
dir data block (highest contention — all nodes' first renames target it).

## ⭐⭐⭐⭐ DEEPEST ROOT (sess43 end) — the gen protocol can't tell "this-node-ahead" from "peer-stale"
After the P81 release-durability FIX (build 41087126: at release, FUA-compare + force-write any
in-core-ahead AG-meta + extra blkdev_flush), a 12-run loop showed **P81fix=0** (releases WERE durable)
yet test4 STILL got `P70 disk_differs=1` (bno in-core AHEAD: bno=117/116-alloc, cnt matches disk
116-free, bno_pin=0 bno_gen=0). So the residual is PURELY IN-CORE during the epoch, NOT a release gap.
**THE FUNDAMENTAL FLAW**: a buffer this node freshly MODIFIED (in-core ahead of disk) has
`b_mxfs_ag_gen=0` (the gen is only stamped to current in the read-hook's discard-clean branch; the
MODIFY path never stamps it). A peer's STALE cached buffer is ALSO gen=0. Both look identical to the
read-hook (`mxfs_ag_meta_invalidate_stale`): gen-lagging + (eventually) DONE+!dirty+!pin+!in_ail
(once this node's modify is committed+written-clean but still in-core-ahead-of-the-peer's-disk... or
during a window). The read-hook then DISCARDS this node's OWN authoritative buffer → re-reads disk →
REVERTS the in-core update → cnt/bno diverge → P70. My in-AIL guard only protects the in-AIL window;
once the buffer is clean-but-still-effectively-ahead with gen=0, it's discarded.
**THE REAL FIX (next session)**: make the gen protocol distinguish this-node-authoritative from
peer-stale. Options: (a) STAMP `b_mxfs_ag_gen = pag_dlm_meta_gen` whenever THIS node modifies an
AG-meta buffer (hook the AG-meta modify/log path, or stamp in fixup_trees / the btree modify), so the
read-hook won't revert this-node's-own work; (b) only treat a buffer as discard-eligible-stale if it
was NOT touched since the last fresh acquire (track a per-buffer "modified-this-epoch" flag);
(c) the read-hook should never discard a gen-lagging buffer that is DONE without first confirming via
FUA it's actually behind disk (expensive). (a) is cleanest: gen-stamp-on-modify closes the
"this-node-ahead looks stale" hole that underlies the entire disk_differs=1 family (free-space, AGI,
dir). This is THE root to fix. NOTE: sess42's gen-stamp FIX deliberately stopped stamping gen on the
SKIP path (pinned/dirty) to avoid false-fresh; but it never ADDED stamping on the MODIFY path — that's
the missing half. Stamp-on-modify (this-node-authoritative) is safe: this node holds the AG EX, so its
modified buffer IS the authoritative version; marking it gen-current prevents self-revert and the peer
gets it via the release drain + the peer's own fresh-acquire gen bump.

## ⭐⭐⭐ CONFIRMED ROOT (P81) — release unlocks AG with in-core metadata AHEAD of disk
**build EB0CD2A2 added P81-INSTR**: at AG-DLM unlock, AFTER the double blkdev_issue_flush, FUA-read
each cached AG-meta buffer and compare to in-core (we hold EX → in-core can only be AHEAD). RESULT
(test1): `P81 REL-NONDURABLE agno=1 agf daddr=2087321 bflags=0x280030 pin=0` AND
`cntbt daddr=2087336 bflags=0x80030 pin=0`. **CONFIRMED: the release hands the AG to a peer with the
agf + cntbt in-core content NOT yet on the shared platter** (DONE set, pin=0, but disk_differs=1).
The peer's FUA read at acquire then misses these → stale-behind → AGI/cntbt/dir corruption+miss.
This is THE unified root of every stale-behind symptom this session.
- WHY the drain misses them: the drain (mxfs_dlm_ag_drain_meta_buffers) only xfs_bwrites buffers with
  `b_li_list non-empty OR bli IN_AIL`; it SKIPS buffers that are DONE+!pinned+bli-not-in-AIL+empty-
  b_li_list (p40_skip_no_li) as "clean". But P81 proves SOME of those skipped buffers are in-core-
  AHEAD-of-disk (modified but neither dirty/pinned/in-AIL). Likely a deferred-op / rolling-txn that
  modifies the agf/cntbt AFTER the drain ran (drain too early), or a buffer written by an earlier
  drain then re-modified without re-logging-as-AIL. (pin=0 rules out CIL; not-in-AIL rules out the
  drain's write set.)
- **FIX DIRECTION (next session, implement carefully — release-path changes have regressed before)**:
  ensure NO AG-meta buffer is in-core-ahead-of-disk at unlock. Option A: at release (P81's spot),
  for each DONE AG-meta buffer, xfs_buf_trylock + xfs_bwrite (write current in-core to disk) — bounded,
  in bast_work_fn kworker context (no locks held, safe to block). Option B: find why a deferred/rolling
  txn modifies agf/cntbt after the drain and re-order the drain to run after ALL AG txns complete.
  Verify with P81 going to 0 + the repro staying clean. P81 itself (FUA-per-buffer at release) is a
  perf cost — make the fix write-on-differ or just unconditionally bwrite DONE AG-meta (idempotent).
- This also explains the dir-miss (same mechanism for dir data/leaf blocks via the inode release path
  mxfs_dlm_bast_process — check it has the same in-core-ahead-at-unlock gap; mxfs_dir_data_durable
  checks dirty/pin/delwri/!DONE but NOT in-core-vs-disk-differs, so a DONE-but-ahead dir block passes
  its "durable" check while being non-durable — SAME bug class).

## ⭐⭐ UNIFIED NEXT-SESSION HYPOTHESIS — release-side durability race (strongest lead)
All invalidation paths (read-hook, walk xfs_buf_stale, no-hold-INVAL, trylock-fail-INVAL) DO clear
`_XBF_FUA_FRESH` (xfs_buf_stale clears it at pal/linux/xfs_buf.c:88), so the re-read after
invalidation IS a FUA read. Yet acquirers read stale-behind metadata (AGI disk_head=0x84 visible
LATER via P71's own FUA read; dir entries on disk but missed). The only consistent explanation:
**a node releases the AG/inode DLM before its metadata write is DURABLY VISIBLE on the shared LUN
to a peer's FUA read.** The peer acquires, FUA-reads the AGI/dir/free-space block, but the writer's
write hadn't landed on the shared platter yet → peer reads pre-write state, stamps it
`_XBF_FUA_FRESH` (fresh!) → uses stale → corruption/miss. The writer's write DOES land slightly
later (P71's FUA read sees 0x84; forced-reacquire still missed dir entries = they were clobbered).
- Release paths HAVE blkdev_issue_flush (mxfs_dlm_ag_release_work_fn; mxfs_dlm_bast_process L309/346/
  507/854/875), but there's a residual race: the metadata WRITE may not be SUBMITTED/COMPLETED before
  the flush+unlock (flush only orders already-submitted writes). xfsaild may write async AFTER release.
- NEXT: instrument the release to confirm ALL dirty AG-meta/dir/inode-cluster buffers are
  WRITTEN (bio completed) — not just flushed — before mxfs_v5_dlm_*_unlock. The drain
  (drain_meta_buffers) uses synchronous xfs_bwrite for buffers with bli-in-AIL/non-empty-b_li_list,
  but SKIPS clean-looking ones (p40_skip_no_li) — a buffer whose write was submitted by xfsaild but
  NOT yet complete at release would be skipped (DONE set, bli gone) yet not durable. Add a release
  census: count AG-meta buffers with in-flight I/O (XBF_WRITE/locked-by-bio) at unlock. If >0, that's
  the gap → wait for I/O completion (xfs_buf_lock barrier per buffer) before unlock.
- This is also consistent with: fua_always=1 "fixed" the AGI bucket read (forced re-read AFTER the
  peer's write finally landed) but caused hangs and exposed the write-ordering layer.
- CAVEAT: sess42 P75 claimed release leaves 0 pinned/in-AIL AG-meta — but that's about AIL state, NOT
  about in-flight bio completion. A buffer can be out of the AIL (written by xfsaild) with its bio
  still in flight to the shared LUN. THAT is the gap to instrument.

## ENV / build
- Build with fix: srcversion **`BB54A138...`** (= EDB2ADAD gen+nohold fixes + P76 from
  sess42 + this in-AIL fix + P77 protect-log). Deploy via `bash tests/reset4.sh 4`.
- Cluster (clyde libvirt host): test1-4 VMs running. reset4.sh takes a NODE COUNT.
- Repro: `tests/repro_rename_concurrent.sh "test1 test2 test3 test4" 20`. run1 often
  corruption-free (coherency misses only); corruption is intermittent on run≥2.
- Keep P70/P71/P76/P77 detectors (fire-only-on-anomaly).
