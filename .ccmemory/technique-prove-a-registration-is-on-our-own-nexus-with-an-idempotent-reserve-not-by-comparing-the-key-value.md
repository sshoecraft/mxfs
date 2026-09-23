---
name: technique-prove-a-registration-is-on-our-own-nexus-with-an-idempotent-reserve-not-by-comparing-the-key-value
description: TECHNIQUE (s102): "the table holds our key" does not say the descriptor is OUR nexus; a matching-scope/type RESERVE completes GOOD only for a nexus…
metadata:
  type: feedback
---

# Prove a registration is on OUR nexus with an idempotent RESERVE, not by comparing the key value

## The gap
READ KEYS and READ FULL STATUS both hand back key VALUES. "Exactly one registration
and it carries our key" does not establish that the descriptor belongs to our I_T
nexus — a different nexus could carry the same value (the key-reuse ambiguity
`dlm/scsipr.c` already warns about elsewhere). Under an all-registrants reservation a
non-registrant's writes are refused, so "we are mounted and writing" is an operational
argument, not a proof, and a gate that rests on it rests on nothing the target said.

## The proof
PR OUT RESERVE with a scope/type matching the reservation already in force completes
GOOD **only** for an I_T nexus registered with the key in the command, and returns
RESERVATION CONFLICT otherwise. Under WRITE EXCLUSIVE - ALL REGISTRANTS every
registrant is a holder, so a matching RESERVE from a registrant is idempotent and
changes nothing (measured on this target, `tests/pr_all_registrants_semantics.sh`).
GOOD therefore means "this nexus is registered with this key" — target-enforced, one
command, no media write.

## Two things that make it safe
1. **Read the reservation FIRST.** On a LUN with no reservation, that same RESERVE
   would CREATE one, and a gate that silently re-armed the cluster's exclusion would
   hide the interval in which non-registrants could write. Having seen a matching
   reservation in force, the RESERVE can only be answered, never acted on.
2. **Call the PAL primitive, not the wrapper.** `mxfs_scsipr_reserve()` classifies a
   RESERVATION CONFLICT against a matching reservation as benign (P304-RESV-CONFLICT-BENIGN)
   and returns 0 — right for a mount that only needs to know exclusion is armed, and
   the exact opposite of what a gate needs, where the conflict IS the finding. Use
   `mxfs_pal_scsi_pr_reserve()` and read -EBUSY.

Measured cost on the 2/tcp rig: 9 ms for three PR IN commands plus this one PR OUT,
with the PR generation unchanged (RESERVE does not bump it, which is what lets the
census be bracketed around it).
