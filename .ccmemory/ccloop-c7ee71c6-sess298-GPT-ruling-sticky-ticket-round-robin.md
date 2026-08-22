---
name: ccloop-c7ee71c6-sess298-GPT-ruling-sticky-ticket-round-robin
description: sess298: D-503 root PROVEN (releaser-relative memoryless nomination + ticket flap) + RULE-5 ruling: fix C = sticky yield_to + last_ex_slot round-robin
metadata:
  type: project
---

# sess298 — D-503 root proven + RULE-5 ruling (fix shape C)

## Root cause PROVEN (P298-ADOPTCENSUS, 0.11.508 sv 3A0B62CA95FAAFA9A6A0BB4, 1545 census lines fleet-wide)
Slow (>800ms) EX grants on hot shared dirs decompose as:
- slept/elapsed = 99-100% (pure queueing; machinery healthy)
- free=0 across ALL 988 slow waits — slot never observed holderless
- caw_try=0 — nominee NEVER self-promotes; every slow grant arrives via releaser direct-handoff CAS (adopt)
- blockers/wait: ~7 reads foreign write-class + ~10 reads foreign shared-class holders
- ticket re-pointed AWAY avg 2.5x/wait; only 44% ever saw the ticket name them; max_el 23.8s observed (ino 55566048)

Mechanism (dlm_caw.c release path ~9074-9230): `caw_pick_next_ex_waiter(ex_w, ctx->node_bit)` picks "first EX waiter after the RELEASER'S OWN slot" — memoryless, releaser-relative. Every intermediate releaser (each PR reader draining) re-runs nomination and OVERWRITES yield_to with its own pick → ticket flaps; only the last-leaving holder's pick gets the direct handoff. A waiter can be passed over indefinitely → heavy tail (p99 2.8s) → dir_reuse round pace shortfall.

## RULE-5 ruling (GPT, this session): fix C = both
1. STATE-RELATIVE SELECTION: when no valid reservation exists, nominee = first eligible EX waiter after `last_ex_slot` (deterministic from slot image; all releasers agree).
2. STICKY TICKET: a valid standing yield_to naming a live registered EX waiter is a RESERVATION — ordinary releasers must NOT overwrite it. It survives PR drains and PR streak-yield batches.
3. `last_ex_slot` advances ONLY on committed EX grant/conversion (direct handoff, self-promote, PR→EX conversion) — NEVER at nomination. PR batches do NOT advance it.
4. Direct handoff must consume the STANDING ticket (caw_handoff_nominee_ok must validate yield_to, not a fresh releaser-relative pick).
5. Streak-yield PR admission may DELAY but not OVERWRITE the standing EX reservation (admit PR batch, keep ticket, grant nominee on drain).
6. CRITICAL deadlock guard: if the standing EX nominee is the SOLE remaining PR holder (upgrader), the release path must atomically CONVERT it PR→EX — must not wait for PR count==0 (nominee itself prevents zero).
7. Upgrader conversion priority stays as exception; an upgrader bypassing the ticket updates last_ex_slot but the standing reservation is preserved and honored next.
8. Invalidation conditions for a standing ticket: nominee deregistered/canceled/fenced/lease-purged (condition stale-clear on demonstrated invalidity, not just the 5s age). NO live-nominee timeout-skip in the first fix.
9. Fresh EX self-promote allowed only if no valid standing ticket or ticket names self.
10. ABA note: ticket is a reservation for "the current EX waiter at slot X"; slot reuse fenced by lease generation — acceptable, document it.

## Board state
Full 28-cell board re-verified PASS on .508 this session (incl. crash_consistency 87s/90s, dir_reuse 101s/120s PASS 58/58 — chronic-marginal, passed this run). P298 evidence in /tmp/tmp.VYmV5C6QY8/p298_test*.txt (window 01:56-02:00Z Aug 15; re-harvest `dmesg | grep P298-ADOPTCENSUS`).

## Next
Implement C in dlm_caw.c (nomination block ~9074, direct-handoff arm ~9183, caw_handoff_nominee_ok, adopt/promote ticket-clear sites), rev 0.11.509, deploy, re-run accumulation+collapse, compare P298 tail (expect tkt_lost→0, p99 collapse toward drain-bounded) and dir_reuse rounds ≥8.
