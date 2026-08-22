---
name: ccloop-c7ee71c6-sess299-503-fixC-landed-0.11.509
description: sess299: D-503 fix C (sticky yield_to reservation + last_ex_slot round-robin) LANDED+BUILT 0.11.509 sv 92165B241B04D8E70772D2E — NOT deployed/verified
metadata:
  type: project
---

# sess299 — D-503 fix C implemented (0.11.509 sv 92165B241B04D8E70772D2E)

Implements the full sess298 RULE-5 ruling (ccmemory
ccloop-c7ee71c6-sess298-GPT-ruling-sticky-ticket-round-robin) in
dlm/dlm_caw.c ONLY (no header change). Seven edits, all commented `sess299`:

1. `caw_standing_ex_resv(s)` — single-bit yield_to naming a registered EX
   waiter (`yt & waiters & waiters_ex`) = a RESERVATION; else 0.
   `caw_last_ex_bit(s)` — bit of last_ex_slot, 0 when NONE. Both beside
   caw_pick_next_ex_waiter (~5560).
2. Release nomination (~9150): `ex_resv` wins (sticky, carried by every
   intermediate releaser); else streak_yield → pr_w; else
   caw_pick_next_ex_waiter(ex_w, caw_last_ex_bit(cur_slot)) — state-relative,
   all releasers compute the same nominee. (Old code: pick relative to
   ctx->node_bit and overwrite on every release = the proven flap.)
3. P6H-PRBATCH arm sets `yield_to = ex_resv` after admitting the PR class
   (delay, never overwrite — ruling item 5).
4. Direct-handoff arm condition extended: fires on `!slot_has_holders(new)`
   OR sole-PR-nominee (`holders_pr == yield_to` and no other holder bitmap
   set) → atomic PR→EX conversion (`holders_pr &= ~wbit` added before
   `holders_ex |= wbit`) — ruling item 6 deadlock guard. Adopt-side
   validation already covers the converted grant (last_ex_slot=us, epoch
   minted by caw_grant_epoch_update as for any handoff).
5. Wait-loop yield defer (~6420): stale-clear now requires age≥5s AND
   `(yield_to & waiters)==0` (demonstrated invalidity). Live nominee never
   aged out (ruling item 8; lease purge clears dead nodes' yield_to+waiter
   bits at ~11405, cancel clears waiter bits → invalidity test covers both).
6. Same conditioning at the initial-acquire stale-clear (~8020); P221
   yield-bound still bounds fresh-acquire courtesy.
7. caw_drop_own_waiter (~4205): clears our yield_to bit in the same CAS
   that drops waiters/waiters_ex (immediate invalidation on cancel).

Unchanged by design: last_ex_slot advances only in caw_grant_epoch_update
(committed EX grants — ruling item 3 already held); upgrader conversion
priority (held-mode≠NL bypass) intact — its grant updates last_ex_slot and
the standing reservation survives (item 7); non-inode / fair_handoff-off
else-branch (yield_to = waiters batch snapshot) untouched.

## Verification owed (next session)
Deploy via `./run.sh 32 caw prep_cluster` (240s budget), run the sess297/298
accumulation chunks, then `./run.sh 32 caw crash_consistency
dir_reuse_coherency` (420s). PASS = dir_reuse ≥8 rounds AND P298-ADOPTCENSUS
tail collapse: tkt_lost→0, chosen_seen ~100%, p99 el drain-bounded. Watch
dlm_fairness (same nomination path as D-501 fix) and P-YT-STALECLR counts
(should drop to near zero — only genuinely dead tickets clear now).
