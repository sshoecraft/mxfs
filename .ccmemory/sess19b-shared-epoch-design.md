---
name: sess19b-shared-epoch-design
description: sess19(ccloop) build 51755ECD: FIXED AGF longest>freeblks (epoch+pagf). cache_coherency STILL FAILS: durable alloc-side bnobt-lost-update (P81 disk_c…
metadata:
  type: project
---

# sess19 (ccloop 4eef1f39) — AGF fixed; cache_coherency still FAILS

## BUILD 51755ECD (all 4 nodes). cache_coherency = FAIL (passed=1 failed=3 of 4).
Criteria NOT met. Marker NOT written.

## FIXED THIS SESSION (solid, KEEP)
- Shared on-disk AG epoch: pag_dlm_meta_gen driven from CAW slot.generation (was FROZEN
  at 1, all read-invalidation dead). Edit A fresh-acquire (~6945): disk_gen !=
  pag_dlm_disk_gen_seen → gen++ + clear AGF_INIT/AGI_INIT (rebuild pagf/pagi from re-read).
- **AGF longest>freeblks WRITE-verify shutdown ELIMINATED** (was 2/4 EVERY run). Root was
  my OWN edit-B reclaim-path AGF_INIT reset pulling pagf backward from lagging disk agf
  while in_ail cntbt was forward. FIX: removed the 3 edit-B pagf resets; kept edit-A's.
- Edit C: in_ail-destaged discard extended to all AG-meta types. KEEP.
- Net: AGF corruption gone; ltbno double-free went constant→INTERMITTENT.

## THE REMAINING BLOCKER (consistent signature, every shutdown)
cache_coherency shuts FS down via the ~50-session core:
  P15 FREE-AG-EXTENT-FAIL-LEFT (freeing a block already free in bnobt → double-free)
  P47-INACT verdict=**DISK-LIVE-same-gen=>A-lost-removal** (inode gens MATCH, not a ghost)
  P81-DEXT **disk_claims_freed=1** DISK-INODE-OWNS-FREED (on-disk inode OWNS the freed block)
  P28 **disk_differs=0 in_ail=0** (bnobt matches disk, block genuinely free in both)
INTERPRETATION: durable ON-DISK inconsistency — inode owns block X, bnobt has X free.
= an **allocation-side bnobt-lost-update**: when the inode was created+allocated block X,
the inode extent-map write persisted but the bnobt's REMOVAL of X was lost/reverted.
P122/P93 (sess121) prevent the xfsaild SPLIT-revert (disk_nr>nr) direction and did NOT
fire (P122=0 P93=0). This is the ALLOCATION-revert direction — uncovered.
ALSO: rename_visibility FAILs with empty content (expected='content_4_20' actual='',
verify prompt ~373-952ms so NOT slowness) = the dir/inode durable lost-update family
(sess121 remaining blocker, [[sess106_lessons]]).

## NEXT-SESSION PLAN (RULE-4)
1. ALWAYS power-cycle+reset4 before any run (back-to-back runs lie).
2. Instrument the ALLOCATION path (xfs_alloc_ag_vextent / xfs_alloc_fixup_trees /
   the bnobt delete in xfs_alloc_update_counters) to catch a block handed to an inode
   whose bnobt-removal does NOT become durable — i.e. log every alloc of block X with
   the bnobt before/after, and on the peer side detect a bnobt write that re-adds X.
   Hypothesis: a peer holding the AG later (or concurrently) writes a bnobt image that
   re-frees X (allocation-revert) — the mirror of P93. Consider extending the P122
   write-side interlock to also block writes that REVERT an allocation (re-add a record /
   grow longest past disk) not just split-reverts.
3. Check P102-ACQ disk_gen advanced before the doomed alloc (is the AG epoch refreshing
   the bnobt at that acquire, or is alloc using a still-cached tree?).
4. Separately: rename empty-content (dir/inode lost-update) — orthogonal dimension.
Diagnostic left ON: P102-ACQ is pr_warn_ratelimited; regate to mxfs_idbg before ship.
Related: [[sess111_reframe_bnobt_red_herring]] [[sess121-bnobt-clobber-writeside-fix]] [[sess117_lessons]]
</body>
