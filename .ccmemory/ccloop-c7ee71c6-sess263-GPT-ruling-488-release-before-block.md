---
name: ccloop-c7ee71c6-sess263-GPT-ruling-488-release-before-block
description: sess263: -488 run3 wedge PROVEN = 3-node cross-AG ABBA deadlock in EFI-finish path; RULE-5 ruling = release-before-block at defer pre-mutation checkp…
metadata:
  type: project
---

# sess263 — -488 second face: cross-AG ABBA deadlock, proven + ruled

## Proof (live wedged fleet, 0.11.491, scaling_curve run3 leftovers)
- Cycle: test1(slot0) holds ag5 waits ag7; test23(slot28) holds ag7
  (pid 7699 dd) waits ag8; test6(slot24) holds ag8 waits ag5. ~14 more
  nodes tree in behind. Blockers bitmasks in P-WAIT-EXTEND decode by hb
  slot; slot map captured in sess263 transcript + handoff.
- All three stacks identical: do_truncate → xfs_setattr_size →
  xfs_itruncate_extents → xfs_bunmapi_range → xfs_defer_finish →
  xfs_extent_free_finish_item → __xfs_free_extent →
  mxfs_ag_dlm_lock (BLOCKING, xfs_alloc.c:4902) → caw_wait_for_grant.
- P1-AGWAIT corroborates: `ag=8 trans_held_ags=[7,] trans_dirty=1` etc.
  Grants retained across rolls by mxfs_trans_migrate_ag_unlocks
  (unfinished EFI work references the AG). No acquisition ordering →
  cycles. Waiter extension ("holders alive") never breaks it.

## RULE-5 ruling (GPT; full text in sess263 transcript)
Release-before-block (option a) is SAFE and chosen:
- A durable EFI does NOT require continuous AG ownership: its extent is
  not in the freespace btrees, so peers cannot allocate/free it.
- Historic "ltbno+ltlen>bno" hazard = releasing with UNCOMMITTED AG
  changes or reusing stale cached btree state — neither applies at a
  clean roll boundary with real ACQ-FRESH reload on re-acquire.
- Async on-disk release via BAST worker is acceptable: it proceeds
  independently of the blocked thread; waiters re-arm BASTs ~5s.
- NOT XFS_TRANS_DIRTY as predicate: xfs_defer_create_done sets DIRTY
  unconditionally BEFORE the first finish_item (verified in-tree).
  Need a dedicated tri-state (NOTDEFER/SAFE/UNSAFE) set SAFE after each
  defer roll, UNSAFE after each finish_item runs.
- When UNSAFE and would-block with retained grants: return -EAGAIN to
  the defer framework (xfs_defer_finish_one:596 relogs + rolls) —
  never block holding grants.
- Later hardening (not this cycle): same protocol for rmap/refcount/
  bmap finish paths and dirty-chain allocations (prepare_ag bounded
  arm); wound-wait via BAST only as a wakeup optimization.

## Implementation plan
In .ccloop/handoff.md (sess263 section): 5 edits — tp tri-state field,
defer.c set/clear points, __xfs_free_extent trylock/drop/-EAGAIN
protocol, agfl_free_finish_item audit, P271 probes. Verify: 3×
scaling_curve 32/caw (reproducer wedges within 3 runs on .491).

## Fleet state at sess263 end
Left WEDGED deliberately (specimen). Recovery step 1 of Next command:
pkill dds, else virsh reset + prep (aged fs survives on LUN).
