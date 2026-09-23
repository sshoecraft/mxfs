---
name: trap-a-poisoned-shell-that-retires-on-the-first-try-hides-the-estale-behind-the-kernels-own-retry
description: TRAP (sess610, D-0346): the control build poisoned the shell and refused the create (P34H-INCARN-POISON, P240 rc=-116) on 10/10 rounds yet mkdir retu…
metadata:
  type: feedback
tags: [D-0346, harness, ESTALE, measurement]
---

# A defect whose user-visible symptom depends on a retry's luck must be asserted at the mechanism

D-0346's board symptom was `mkdir: Stale file handle`. The deterministic harness
reproduced the whole kernel-side chain on the control build every round
(`P34H-INCARN-POISON src=reload disk_mode=0`, then `P240-QUAR-NSOP-REFUSE
op=create rc=-116 comm=mkdir`) — and mkdir still returned 0 with a 3-4 s stall,
because `P34H-POISON-EVICT try=1 i_count=2` retired the shell and the op-entry
refusal was retried on a fresh iget. On the board the previous row's cached
children had pinned the shell (`P34H-POISON-UNRETIRED tries=5`) and the ESTALE
surfaced. Stat-ing the children in the harness did not reproduce the pin.

So a harness that scored only `rc`/"Stale file handle" would have read the
control as clean and the fix as vacuous. The round's verdict counts the
mechanism lines (poison, refuse) alongside rc, and a round in which the reader
never read the free image at all is VACUOUS, never OK. Same family as
trap-a-control-arms-expected-behaviour-written-from-reasoning-hides-the-second-defence.
