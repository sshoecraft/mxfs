---
name: ccloop-c7ee71c6-sess390-GPT-ruling-noino-fence-convoy-intents-lifecycle
description: sess390 RULE-5 ruling: noino release fence — do NOT exempt intent items; convoy-aware stall accounting w/ attribution + absolute wall (B); INACTIVATI…
metadata:
  type: project
tags: [sess390, ruling, noino, fence, EFI, intent, convoy, 474, inactivating, lifecycle, readopt]
---

# sess390 RULE-5 ruling (gpt-5.6-sol) — noino release fence vs. frozen EFI

## Evidence brought
25-AG wedge (sess389): P-AILMIN frozen item type=4662=0x1236=XFS_LI_EFI on both nodes, static lsn; test7 probe armed, ZERO P129 lines -> EFI was the only frozen item (inode item re-logged past the fence target by xfs_trans_roll; EFI not). Owner = inodegc extent free blocked in P1-AGWAIT on the SHARED AG held by the peer ~13 s (peer readopt=342). Fenced inode X already freed (IRECLAIMABLE/absent), 40 peer EX waiters (ino reuse). Convoy, not deadlock.

## Ruling
- (A) "exempt XFS_ITEM_INTENT items from the fence" — REJECTED as a general fix: an un-done intent is evidence of unfinished multi-txn work whose continuation commits BUF/INODE items AFTER the snapshot target; per type: EFI least dangerous (conservative, extent not yet free) but the BASTed inode may itself be the one being truncated; RUI/CUI/BUI/ATTRI/XMI must not be ignored; recovered intents neither. Invariant #1 needs QUIESCENCE of ops admitted under the grant + durability — (A) establishes neither. A narrow EFI exception might be provable only for a truly absent inode with ownership independence — not by type filtering.
- (B) REQUIRED: convoy-aware stall accounting — while a local task is in a bounded per-AG CAW wait attributable to the frozen item (EFI -> extent AG; BUF -> daddr AG), stalls are not chargeable; keep an ABSOLUTE fence deadline that unrelated/repeated waiters cannot renew; telemetry: raw frozen duration, chargeable/suppressed counts, fence age; hard wall must cover the real max handoff path.
- (C) REQUIRED: close local re-adoption once a BAST is pending; bounded batching/publication repair — makes the convoy genuinely bounded (otherwise (B) turns shutdowns into long stalls).
- (D) drop ILOCK across AG wait in inactivation — not the cure; separate lock-order change only with restart/revalidation.
- LIFECYCLE (item 1, first in order): xfs_iget(INCORE) -EAGAIN for INEW/IRECLAIM/INACTIVATING (and -ENOENT for NEED_INACTIVE nlink==0) is "inode still locally active", NOT "no inode" — retain the DLM grant, mark release pending, requeue at lifecycle completion (explicit notify after truncate defers + ifree), then drain/flush before unlock. Today the fence already completes between the last EFD and xfs_inactive_ifree = pre-existing hazard. Use a safe reference-free lookup (rcu + i_flags_lock, or a per-ino completion tied to the grant), never a raw pointer after unlock. Verify no cycle: peer holds AG A + BASTs X + waits X while local inactivation of X holds X and waits A — peer must release AG without waiting for X (bounded reserve already does).
- AIL scan under ail_lock is coherent; don't keep item pointers after unlock; for stall accounting compare the qualifying LSN but ALSO record the raw head.
- Audit the per-AG drain's "non-BUF/INODE items are nonblocking" rule separately (RUI/CUI/BUI/XMI AG-relevant).

## What sess390 did with it
(B) landed 0.20.1 (P-NOINO-CONVOY), plus the stack-proven second root: nonblock AG acquire parked in wait_demote with ILOCK held (0.20.2 P-AGTRY-DEMOTING). Lifecycle item and (C) still open — see D-NOINO-RELFENCE-AIL-FREEZE-474 / D-RSYNC-LAP-PACE-AG-SHARING-388 next steps.
