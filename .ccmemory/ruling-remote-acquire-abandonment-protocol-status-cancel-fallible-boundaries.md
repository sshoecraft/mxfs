---
name: ruling-remote-acquire-abandonment-protocol-status-cancel-fallible-boundaries
description: Design consult ruling (Astra, sess585, D-0958): lifetime-first, exact CANCEL w/ tombstone, status = CONFIRMED_ABSENT, explicit fallible ilock; no gen…
metadata:
  type: reference
tags: [ruling, dlm, tcp, acquire, D-0958]
---

# Ruling: bounding a remote inode acquire whose live master never answers (D-0958)

Consult answered 2026-09-11 (sess585) on the proposed LOCK_STATUS / LOCK_CANCEL / fallible-boundary increment. The parts that constrain future work:

## Verdict
- For a caller that genuinely cannot unwind (dirty transaction, writeback, inactivation), there is NO safe bounded completion under persistent request loss: the only safe actions are wait with exclusion preserved, transport repair, or an audited unwind point. Never membership escalation from the acquire path. So the defect closes by widening the fallible class + exact abandonment + honest reporting, not by a timer on non-fallible callers.

## Shipping order it gave
1. Acquisition LIFETIME first: a grant is solicited by the logical acquisition (acq_seq), not by the existence of the one-second pending entry. A grant landing between attempt windows must be kept/adopted, not bounced. Register before the first send; keep the state across every re-send and classifier restart.
2. Exact terminal CANCEL: master keeps a cancellation tombstone per (sender, owner_inc, acq_seq) so a late re-send cannot recreate the waiter; CANCEL on a committed/undelivered grant retires it at the master (do not rely on the delivery bounce); CANCEL has an ack; cleanup is DLM-owned and task-independent.
3. Status lookup: QUEUED | GRANTED | NOT_FOUND | NOT_MASTER | RECOVERING. NOT_FOUND is CONFIRMED_ABSENT / REQUEST_NOT_REGISTERED — an observation, never "lost at sender". Ordering: a negative answer is causal only if REQ and STATUS are processed through one ordered ingress. Keep three evidences separate: queue confirmation, status reachability, confirmed absence.
4. Nonce history must cover allowance x rate: 4 nonces at 1/s contradicts a 15 s allowance; ~16. Acquisition table must not evict live/draining records.
5. Explicit error-returning acquire interface for audited sites (open re-audit, getattr/stat, the read path, then readdir); verdict checked immediately at the acquisition, never at syscall exit; unlock exactly the components acquired.
6. Fatal-signal handling only on converted paths; abandonment arbitrated atomically against installation; record outlives the task.
7. Transport repair as a separate rate-limited subsystem with no membership/authority side effects — never from the acquire path.

## Do not ship
- `current->journal_info == NULL` as a generic permission to fail.
- GRANTED re-delivery while the no-pending-entry bounce rule stands (status GRANTED completes, original grant arrives, bounce retires an INSTALLED grant -> conflicting authority).
- A CANCEL that only deletes a currently visible waiter.
- K consecutive NOT_FOUND presented as a factual sender-loss diagnosis.

## Bounds
- K and the silence bound are policy, not derivable from P=1 s / D=15 s. Never derive them from drain duration, holder I/O latency, membership timeouts, the 180 s budget or a test's window. A false suspicion may cause an orderly failed acquisition, never conflicting authority.
