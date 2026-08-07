---
name: ccloop-c7ee71c6-sess47-TAIL13-two-phase-retire
description: sess47: 0.11.384 fleet = A-prime v2 SHIPPED (two-phase retire: wr_epoch stamp at completion, drop only after flush-epoch advance; reset on re-record)…
metadata:
  type: project
---

# A-prime v2 — two-phase retire SHIPPED (0.11.384, 2E1BB7394083514371447C8, fleet-wide)

## Why v2 (383 recurrence decode)
383's fatal (test2 t=1009.97, ring /root/c2_383_t2_*.dmesg) had ZERO store prints: the record was retired at bio write COMPLETION — but completion on this LIO stack = target write cache (P143/mkfs precedent), and cold FUA fills bypass that cache → retired record + stale platter = uncovered window.

## v2 mechanics (xfs_mxfs_dlm.c store)
- mxfs_iunl_rec += wr_epoch (0 = write pending).
- retire_range: stamps wr_epoch = m_mxfs_flush_epoch at write completion; drops any record with wr_epoch && current_flush_epoch > wr_epoch (lazy sweep in the same walk). A target-DROPPED write past a flush loses coverage (target bug class → escalation would be FUA cluster writes); until a flush, the overlay corrects every stale fill.
- record(): update path resets wr_epoch=0 (re-unlink of same ino = new pending write).

## Verified on deploy
prep 32/32, reap repro CLEAN ×2 scenarios, matrix 9/9.

## Proof soak (relay continues; producer ~1/5 cycles, test2-biased)
cycle = lap → idle 250s → lap → matrix → sweep(P53|Shutting|error -117 + P-IUNLSTORE-OVERLAY count). SUCCESS = overlay prints appearing WITH P53=0 across ≥8 cycles. P53 recurrence discriminator: overlay-print present before it = overlay raced/incomplete; absent = unhooked fill path (audit P34D src=plain + any raw dinode readers) OR flush-epoch advanced before platter caught up (target ignores flush → FUA-write escalation).
Rings so far: test2 ×5 (transcommit_incore, cyc6, c2_382, c2_383 + ifree117_run2), test9, test10, test32.
