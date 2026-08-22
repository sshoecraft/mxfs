---
name: ccloop-c7ee71c6-sess285-501-p291-exwin-probe-landed
description: sess285: D-501 RULE-4 probe P291-EXWIN landed+built 0.11.502 sv AA10BE63A46357BC8190D80 — uniform per-path EX-grant log; NOT yet deployed/run
metadata:
  type: project
---

# sess285 — D-501 measurement probe landed

## P291-EXWIN (dlm/dlm_caw.c, 0.11.502 sv AA10BE63A46357BC8190D80)
One line per successful exclusive-class INODE grant, every path:
- "promote" — caw_wait_for_grant self-promote (post-CAS success)
- "adopt" — direct-handoff adoption on sight (beside P6H-ADOPT)
- "cold" — mxfs_dlm_caw_lock compat-add (incl. in-place PR->EX upgrade)
- "claim" — fresh slot claim
- "convert" — convert-fn upgrade CAS (rc==0 gated)
- "mint" — release side, CAS-COMMITTED direct-handoff winner (single bit)
- "nom" — release side, CAS-committed un-minted single-bit EX ticket

Helper caw_exwin_log after caw_handoff_nominee_ok; gated LTYPE_INODE +
mxfs_mode_can_write; cap 20000/module-load; fields:
`ino path mode slot waited_ms yt wex realms`.

NOTE: P6H-HANDOFF prints PRE-CAS (over-logs on -EAGAIN retries) — that is
why mint/nom were added at the post-CAS point (~9160, after the
caw_send_grant_mcast pair). Do not trust P6H-HANDOFF counts for
distribution.

## Key code facts established
- Nomination = caw_pick_next_ex_waiter(ex_w, releaser_bit): first EX
  waiter strictly AFTER the releaser's own bit, cyclic. No persistent
  cursor — rotation is relative to whoever releases.
- Direct handoff (default on): last-holder release CAS itself makes the
  winner holder, clears its waiter bits, zeroes ticket.
- Waiter-side ticket honor requires node_held_mode==NL: upgraders
  (holding PR etc.) BYPASS the ticket (sess130 conversion priority).
- Streak yield: after MXFS_CAW_EX_STREAK_YIELD consecutive EX tenures
  with PR waiters present, ticket goes to whole PR class.
- caw_adopt_retained is mount-adopt-window only — irrelevant here.

## Decision rule for the next run
Aggregate all-node dmesg P291-EXWIN on the hot dir ino by realms:
- Same subset repeat-wins before others' first win → H1 (bias) confirmed.
- Clean ascending rotation with ~0.5-1s spacing → H1 refuted; defect is
  per-handoff cadence (tenure+handoff gap × 32 ≈ 25s ≈ observed makespan;
  16 rounds mostly complete within a node's first tenure via MHT).
RULE-5 consult before any fix.
