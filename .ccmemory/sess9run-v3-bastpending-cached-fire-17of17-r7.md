---
name: sess9run-v3-bastpending-cached-fire-17of17-r7
description: sess9 v3 (build 2493D345): gen-moved abort arms i_dlm_bast_pending + ilock_end fires on CACHED&&pending (tds pace fix). 4/tcp r7 17/17.
metadata:
  type: project
---

# v3 — abort re-fire channel (tds pace) + second 17/17

## tds r6 pace collapse (build 4353CDBB)
tcp_dlm_scaling 0/4: node1 18/150 rounds (~3.3s/handoff; healthy = 150 rounds in ~0.5s), node2 60, node3 73, +3 residual ghosts. Cause: FIX-26 v2's gen-moved abort set state=CACHED but NOTHING re-fired the release — the requesting peer waited its 6s ACQUIRE_WAIT retry per occurrence.

## v3 (build 2493D345)
1. gen-moved abort: state=CACHED **+ i_dlm_bast_pending=true**.
2. mxfs_dlm_ilock_end last-holder fire condition extended: `state==BAST || (state==CACHED && i_dlm_bast_pending)` → DEMOTING + queue bast work. (i_dlm_pin_count is vestigial — never incremented; ilock_end is the only fire site that matters.)
bast_process clears bast_pending (line ~11769); MHT-dwork setters of the flag get a faster re-fire too (aligned with their purpose).

## Results ladder (4/tcp full suite, clean cycle each)
r5 (4353CDBB) 17/17 first ever → r6 (same) 16/17 tds pace → **r7 (2493D345 v3) 17/17**. r8 repeat launched.

## Session fix stack (all in 2493D345)
FIX-26v3 (bast mid-drain-upgrade release abort + CACHED + bast_pending refire), FIX-27 (EDEADLK goto loop, panic fix), FIX-25-widened (ioend admit under PR), FIX-28 (publish phantom skip), P9-LFREE/P13-realns/P9-NLEDGE ledgers.
