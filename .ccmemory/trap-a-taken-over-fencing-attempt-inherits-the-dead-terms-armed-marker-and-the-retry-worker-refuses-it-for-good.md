---
name: trap-a-taken-over-fencing-attempt-inherits-the-dead-terms-armed-marker-and-the-retry-worker-refuses-it-for-good
description: TRAP (s71a cuts 3/4, D-FENCE-CRASH-MATRIX-UNTESTED): fence_takeover kept the dead prover's MAY_HAVE_RUN; the successor's first prove was NO_RESERVATI…
metadata:
  type: feedback
tags: [fencing, recovery, takeover, retry, crash-cuts]
---

# A per-attempt "may have run" marker must be scoped to the term that armed it

Sweep s71a (2/tcp, qnap) cuts 3 and 4: the prover A parked with its fencing
attempt for B1 armed (MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN durable) and was
destroyed.  B's host booted first and mounted alone.  Its journal, tags in
order:

- it fenced the dead prover A1 through the sole-survivor gate (a single-
  holder WE(1) under its own key), certified and sealed it;
- it took B1's attempt over (P238-FENCE-TAKEOVER, term 1->2) — the takeover
  CAS bumped the term and the prover but left the dead term's armed bit;
- its one prove returned NO_RESERVATION at phase PRECOMMAND (P-PR-NORESV:
  held=1 type=0x1, want 0x5/0x7 — the WE(1) gate for A1's recovery was in
  force), logged P238-FENCE-PENDING retry=automatic;
- A1's recovery published and the gate went back to WE-AR 12 s later;
- the retry never ran: mxfs_disklock_recovery_fence_retryable refuses any
  descriptor with the armed bit ("ambiguous — needs reconciliation"), both
  from the latch (v5_fence_retry_one disarms on rc 0) and the sweep;
- 50 s of P238-FENCE-HOLDER-STATE (holder = our own incarnation) and
  P236-CLAIM-UNCERTIFIED, then "MXFS mount recovery barrier failed", mount
  rc 32, B1's slice never replayed, its fsynced files not visible.

Reachable in production: a prover crashing right after arming, on a target
that purges registrations with the session, with the victim's host back
first.  Cuts 1 and 2 (unarmed descriptor) recovered by boot succession.

Design ruling (Astra, s72): an inherited arm is not a submission by the
successor; the marker is CURRENT-TERM state.  The takeover folds the dead
term's value into a separate PRIOR_TERM_MAY_HAVE_RUN history bit (which
forbids reading key absence as the dead command's success, and nothing
else) and clears the current bit with the new term; the retry predicate keys
on the current bit only.  Also required: the NO_RESERVATION precheck must
not arm the new term (it does not — the reservation-form check precedes the
arm callback; no P304-FENCE-ARM for the slot in the journal).  Rejected
shapes: retry keyed on volatile in-memory knowledge (not crash-closed);
deferring the takeover while another gate is in force (scheduling, not the
repair).  Fix: 0.89.9 dlm/disklock.c fence_takeover + disklock.h flag.
