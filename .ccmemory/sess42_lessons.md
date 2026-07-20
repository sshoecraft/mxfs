---
name: sess42_lessons
description: sess42 (2026-06-01) — FIXED the false-fresh AG-meta gen-stamp bug (eliminated AG free-space double-alloc corruption under 4-node rename); proved remaining AGI/dir corruption is the same stale-while-pinned read-coherency root in other domains. Cluster=clyde libvirt VMs.
metadata: 
  node_type: memory
  type: project
  originSessionId: 917725da-ce53-4427-8efd-da84713d0c49
---

# sess42 — AG free-space double-alloc FIXED; remaining corruption root-caused

## Cluster/env (was the sess41 blocker)
- The dev host **IS `clyde`**, the libvirt host. test1–32 are VMs here (`virsh list --all`).
  They were ALL **shut off** at session start (why sess41's reset4 "failed"). Boot:
  `virsh start test1 test2 test3 test4`, wait ~30s for DHCP → resolve as
  `testN.vm.localdomain` (bare name works via search domain). SCST target on clyde
  serves /dev/sda (SCST_FIO, CAW works); /src is NFS so mxfs.ko is cluster-visible.
- **`tests/reset4.sh` arg is a NODE COUNT** (`bash tests/reset4.sh 4`). sess41 ran it as
  `reset4.sh mkfs` → bash `${arr:0:mkfs}` → 0 nodes → false RESET_FAIL. Not a real bug.

## PROVEN + FIXED: false-fresh AG-meta gen stamp → free-space double-alloc
- Detector method (the winning RULE-4 pattern): a **fire-only-on-corruption** pr_warn at
  the exact `XFS_IS_CORRUPT` site, dumping buffer daddr + `b_mxfs_ag_gen` vs
  `pag_dlm_meta_gen` + flags + a **live FUA disk-vs-incore memcmp** (new helper
  `mxfs_ag_buf_disk_differs()` in xfs_mxfs_dlm.c; LBA = `bm_bn + bt_sector_offset`).
  Near-zero overhead, does NOT hide races (unlike mxfs.instr=1 which is 100x slow).
- P70 at `xfs_alloc.c` `xfs_alloc_fixup_trees` i!=1 (both cnt & bno branches) showed:
  `bno_gen=2 (==pag_gen → "fresh") bno_disk_differs=1 (STALE) pin=1`, cnt matched disk.
  The cached bnobt buffer was marked fresh yet held a stale post-mkfs whole-AG-free view
  → allocator double-allocated → cnt/bno disagree → corruption + shutdown.
- ROOT: `mxfs_ag_meta_invalidate_stale()` stamped `b_mxfs_ag_gen = pag_dlm_meta_gen`
  **unconditionally**, even when it SKIPPED invalidation (buffer pinned / BLI-dirty /
  delwri). A stale un-refreshable buffer thus got marked "current gen" → every later
  read-hook saw gen-current → never re-read it → stale free-space frozen authoritative.
- FIX: only advance the gen when the buffer is genuinely fresh — already gen>=current
  (no-op) OR we actually cleared XBF_DONE (clean+unpinned+!delwri). In the skip case,
  leave gen lagging. Result: **P70 0/8 runs** (was firing every corrupting run). The AG
  free-space double-alloc corruption is gone.

## PROVEN + FIXED #2: EX-acquire walk SKIP-no-hold left a stale AGI reusable
- The walk's P14 SKIP logs are UNGATED (already in dmesg). Correlation on test1:
  STALED(2087322) ... then SKIP-no-hold(2087322) ... then 1.6ms later P71
  agi_disk_differs=1 corruption. The walk skipped the AGI buffer because b_hold==0, left
  it XBF_DONE+stale, it was reused stale.
- FIX (mxfs_dlm_invalidate_ag_meta b_hold check): for a b_hold==0 AG-meta buffer, clear
  XBF_DONE|_XBF_FUA_FRESH under b_lock so reuse re-reads. SAFE because no-hold ⇒ clean (a
  BLI/delwri would hold a b_hold ref). Result: AGI corruption (P71) → 0.

## REMAINING #3 (OPEN): finobt — the hard-core pinned-buffer staleness
- After fixes #1+#2, shutdown now via `xfs_ialloc.c:1513 i!=1 && j!=1` in
  `xfs_dialloc_ag_finobt_near` (free-inode btree), 13× on test3. NO P14 finobt SKIP
  correlation → likely a CONTINUOUSLY-PINNED finobt buffer during the dialloc storm that
  neither fix covers (gen-stamp leaves pinned bufs gen-lagging but can't refresh them;
  no-hold only covers clean no-hold bufs). NEXT: add a P72-style finobt detector
  (disk_differs + pin/dirty) at xfs_ialloc.c:1513 to localize; then a comprehensive
  re-acquire refresh that resolves pins, or a release-side no-pinned-AG-meta guarantee.
- Current deployed build (both fixes + detectors): srcversion **`5A783D273D8656DBB9DAD99`**.

## REMAINING (cache_coherency still fails — cluster still shuts down)
Same stale-while-pinned read-coherency root, OTHER domains:
1. **AGI unlinked-list** (3/4 nodes): `xfs_iunlink_remove_inode:603` agi_unlinked[bucket]
   garbage. P71 probe proved **agi_disk_differs=1, agi_gen=0** → in-core AGI is STALE vs
   disk, used during inode inactivation (the next run's `rm -rf`). My gen-fix correctly
   leaves it gen-lagging, but the lazy hook still can't refresh it while pinned → used
   stale → lost update on the unlinked list.
2. **Dir-block EFSBADCRC** (error 74) at xfs_da_read_buf — bad on-disk CRC → block was
   overwritten → block double-alloc may still occur silently (both trees agree on a used
   block). NOT yet proven double-alloc — NEXT: cheap always-on alloc-overlap detector.
3. **Coherency MISSES** (run1 TOTAL_FAILS=3/3/3/0, no corruption): dir-block lost-update
   (`DIR-STALE-SKIP` in xfs_da_btree.c — peer's renamed dirent in a block this node has
   pinned/dirty, can't refresh). Dir-gen path has NO false-fresh bug (already correct).

## ⭐ PIVOTAL: a SECOND free-space corruption is WRITE-SIDE (not read-coherency)
After fixes #1+#2, P70 STILL fires (test2) with a NEW signature:
`pag_gen=1 holders=17-20 cnt_disk_differs=0 bno_disk_differs=0 bno_pin=0 bno_dirty=0
fbno=24 flen=260891`. BOTH trees MATCH disk yet disagree → the ON-DISK bnobt/cntbt are
genuinely inconsistent. This is NOT stale-cache (my fixes handle that) — it's a
**WRITE-SIDE / release-drain bug**: a node releases the AG (or checkpoints) with bno vs
cnt in an inconsistent on-disk state (non-atomic writeback of the two btree blocks). Low
gen + holders=20 = the rm-rf inactivation storm. **This redirects sessions 20-42's
read-coherency focus to the WRITE side.** Next: audit `mxfs_dlm_ag_drain_meta_buffers`
(skips bufs whose BLI not IN_AIL & b_li_list empty — could skip bno while flushing cnt);
ensure release flushes ALL AG free-space btree blocks atomically before
`mxfs_v5_dlm_ag_unlock`. The EFSBADCRC dir-block + iunlink are likely downstream of the
same half-written on-disk AG metadata. Also saw hung `mv` (122s, load 14) =
corruption→shutdown→DLM-grant-stall cascade.

## sess42 end — drain-skip-of-dirty DISPROVEN; bug is a bad WRITE, origin TBD
P73-INSTR (drain p40_skip_no_li, logs bnobt/cntbt skips): the drain skips bno/cnt but they
are CLEAN (pin=0, bip=NULL, no dirty/delwri) → correctly skipped. So release is NOT
leaving dirty free-space blocks. Combined with P70 (reader clean/unpinned/gen-fresh,
disk_differs=0): the reader faithfully reads a corrupt ON-DISK bno/cnt pair some node
wrote inconsistently. cnt by-size gave a giant (24, 260891 ≈ whole-AG) free extent that
bno by-block lacks → over-coalesced/wrong free record on disk. NOT a read-coherency skip.
Also note: at RELEASE all AG-meta is clean (pin=0), so pinned blocks only exist during a
node's OWN active modify (current content, not stale) → the "stale-read-at-modify"
sub-hypothesis is weak; lean toward (b) double-alloc-downstream / a free-path inconsistency
under 4-node concurrency. NEXT: cheap always-on alloc/free extent-overlap detector
(catch block double-alloc directly), and/or dump both leaf blocks' records at P70 to see
the exact disagreement (extra record vs length mismatch). Current build E85016540CE86975D1D4180.

## sess42 FINAL refinement — likely a LOST cnt-tree UPDATE
Record-level P70 (test4): cnt gave free extent (118, 260797) but bno's record is
(119, 260796) — diverge by ONE block (118). Correlation showed the walk STALED+refreshed
the bno (`verdict=STALED`) ~100ms before — so bno was fresh; bno_disk_differs=1 =
in-core AHEAD of disk (this node's just-done alloc of 118, legit). cnt (disk_differs=0)
still shows 118 free → a PRIOR allocation removed an extent from bno but NOT from cnt =
**lost cnt-tree update**. So the residual free-space corruption is most likely a
cnt-by-size update that didn't stick (stale/pinned/discarded cnt buffer during a prior
`xfs_alloc_fixup_trees`), NOT a bno read-staleness. test2 (disk_differs=0, holders=17-20)
is the downstream on-disk-baked version. NEXT: instrument the cnt cursor's leaf
daddr/gen/disk_differs at the moment of the cnt update in fixup_trees; a stale cnt buffer
there = the lost-update source. Builds carry P70/P71/P72/P73 fire-only-on-error
detectors (keep them). Final build srcversion 2A2A5CE7C6B1F52115F1964.

## sess42 NEGATIVE RESULTS + final narrowing (instrumented, don't re-chase)
- P73: release drain skips bno/cnt only when CLEAN (not dirty). 
- P75: at AG-DLM unlock, ZERO bno/cnt pinned/in-AIL/dirty (P75=0 with cumP70=16) →
  release FULLY checkpoints free-space btrees → stale buffer is NOT a release-leftover.
- P74: cnt IS modified while gen-stale, but that's the normal this-node-AHEAD state
  (pinned, disk_differs=1 = own uncommitted allocs); benign by itself.
- Correlation: on the corrupting node the BNO buffer walk verdict = STALED (walk DID
  refresh it) → re-acquire read-staleness is NOT the cause; both trees re-read fresh yet
  diverge. **=> the inconsistency is produced DURING the MODIFY, not from a stale read.**
- STRONGEST remaining hypothesis: an MXFS txn/defer-chain interleaving that drops the AGF
  (agbp) buffer-lock serialization mid-xfs_alloc_fixup_trees (two allocations interleave
  bno-vs-cnt updates → inconsistent in-core → release writes it to disk). Re-examine
  mxfs_ag_dlm_unlock_deferred / t_mxfs_ag_unlocks migration (sess26) + bast_work_fn
  pag_dlm_demoting + AGFL coherency (btree split pulls blocks from AGFL; stale AGFL →
  btree block at wrong agbno). holders=1 at the P70 → a PRIOR txn left bno≠cnt; instrument
  to catch the prior txn that updated bno without a matching cnt update.
- Last build with all detectors (P70-P75): srcversion EDB2ADAD4CE4EF80E1EF39F.

## THE UNIFYING ROOT (for next session)
Lazy gen-based invalidation **cannot invalidate a buffer that is pinned/locked/dirty at
access** (it XBF_TRYLOCK-skips). The stale buffer is then used and modified on a stale
base = lost update. Closing the "marked-fresh-while-stale" sub-case (this session) was
necessary but not sufficient. The real fix is RE-ACQUIRE/RELEASE side:
- Prove the EX-acquire walk `mxfs_dlm_invalidate_ag_meta` skips the stale AGI/bnobt
  (instrument SKIP-no-hold/SKIP-trylock-fail for GEN-STALE AG-meta bufs at the gen-bump
  acquire). The walk does xfs_buf_stale pinned bufs IF it can trylock; it skips no-hold
  and trylock-fail. drain_meta_buffers skips bufs with BLI not IN_AIL & b_li_list empty.
- Candidate fixes: (a) bounded-retry the walk's skipped stale AG-meta bufs (transient
  locks from async writeback clear fast); (b) POST-read forced re-read of a gen-stale
  clean buffer in xfs_read_agi / xfs_btree_read_buf_block (we hold the lock after
  xfs_trans_read_buf, so safe for clean bufs); (c) guarantee release drain leaves NO
  pinned/dirty AG-meta buffer (invariant #1). Inode-cluster (di_next_unlinked) is a
  separate coherency domain (i_dlm) — audit it for the same pinned-skip limitation.
- DANGER: never force-re-read a DIRTY/pinned buffer that holds THIS node's legit pending
  changes — that clobbers them. The unsolvable-locally case is "stale base already
  dirtied"; prevent it by refreshing BEFORE first modification (re-acquire walk must be
  complete), not after.

## Build / files (all still building clean)
- Deployed build (gen-fix + P70/P71 detectors): srcversion **`C6970FF9295073C515D9AB6`**.
- Changed: `xfs/xfs_mxfs_dlm.c` (gen-stamp FIX + `mxfs_ag_buf_disk_differs`),
  `xfs/xfs_mxfs_dlm.h` (decl), `xfs/libxfs/xfs_alloc.c` (P70 both branches),
  `xfs/libxfs/xfs_inode_util.c` (P71 AGI probe). sess41 btree-block hook in
  `xfs/libxfs/xfs_btree.c` kept. KEEP the detectors (error-path only).
- Full handoff in `/src/mxfs/state.md` (sess42). See also [[sess41_lessons]],
  [[sess39_lessons]], [[feedback_timing_is_first_class]].
