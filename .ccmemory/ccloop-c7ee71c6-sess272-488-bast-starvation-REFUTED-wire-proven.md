---
name: ccloop-c7ee71c6-sess272-488-bast-starvation-REFUTED-wire-proven
description: sess272: -488 BAST-send starvation REFUTED by tcpdump (test2 sends ~256ms cadence, test27 receives+P12 fires); permanence = dead-owner bit + torn-rep…
metadata:
  type: project
---

# sess272 — -488 fifth face: wire path exonerated, mechanism narrowed

## Refutation (direct measurement on the live wedge)
- tcpdump on test2 (`udp port 7602`): the blocked rsync 13975's caw_wait_for_grant
  re-BAST (dlm_caw.c:5886, 100ms nominal → ~256ms observed with poll backoff)
  multicasts CONTINUOUSLY to 239.66.83.1:7602. Send side healthy.
- tcpdump on test27: packets arrive (M flag); P12-AGBAST-RX ag=3 fires and
  P5N-AG-ORPHAN-NAK ag=3 disk_held=0 repair=0. Rx path healthy fleet-wide.
- sess271's "no ag=3 BAST since 17:16:46" was a LOG artifact: P12-AGBAST-RX is
  pr_warn_ratelimited at ONE callsite shared by ALL AGs — heavy other-AG rx eats
  the ratelimit budget. NEVER infer BAST absence from P12 silence; use tcpdump.

## Why the livelock never self-heals (now proven, not a defect of the BAST path)
- Every live node correctly answers disk_held=0: the stranded EX bit28 belongs to
  DEAD test28. The readopt strand-repair (xfs_mxfs_dlm.c 41629) requires the OWN
  bit — correct. A dead node's bit is only cleared by lease purge, which is
  blocked by the victims' torn -117 foreign replay (#1 territory).
- So -488 permanence = (birth: silent strand on test28) + (dead owner) +
  (replay freeze blocks purge). The missing piece is loud escalation, not re-BAST.

## Readopt-storm anatomy (test28 17:15:44, prior boot journal)
- readopt 356→387→452 in ~200ms (~500/s), sched=1 in every P12 print;
  holders oscillating 1↔0 with rsync 5582 re-acquiring.
- Readopt gate requires !sched && !dm && !rp, so fires only in windows where the
  work fn's bail paths cleared sched. Cycle: readopt(cached=1,sched=1) → work →
  bail-holders (clears sched) or COMMIT→unlock → re-acquire → strand → readopt.
- After 17:15:54 test28 logged ZERO ag=3 events: either stuck sched=1/demoting=1
  latch (rx handler has NO acting branch when sched=1 → total deafness) or
  ratelimit. Post-mortem indistinguishable → fix must probe both.

## Open (RULE 4)
Birth unproven: H-a silent unlock failure (caw_unlock_gen_body paths a/b/c:
find_slot -ENOENT→rc=0 @8573, find_slot err @8577, CAS non-EAGAIN @8953) vs
H-b stuck latch post-COMMIT. Fix legs queued for RULE-5: loud probes on silent
unlock paths, AG unlock wall-clock deadline (extend sess6 ICLUSTER fix), unlock
verify-the-clear + re-arm tenure on failure, stuck-latch probe, loud escalation
when dead bit + blocked replay. NOT a re-BAST leg.

## Infra
test1 ssh by IP (192.168.120.186) now permission-denied; hostnames work.
