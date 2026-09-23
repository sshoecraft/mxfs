---
name: trap-read-keys-does-not-say-which-nexus-holds-a-key-and-lost-registration-has-four-causes
description: TRAP: READ KEYS never says WHICH nexus holds a key (needs READ FULL STATUS), and a mounted node losing its own PR registration has four causes, not o…
metadata:
  type: feedback
tags: [scsi-pr, fencing, evidence]
---

# Reading SCSI PR evidence: three ways a confident conclusion is wrong

Surfaced by a design consult on the unmountable-volume defect (0950), which found the ledger
record's stated root chain was **plausible but not established** by the evidence it cited.

## 1. READ KEYS does not say which nexus holds a key

A key appearing in READ KEYS proves the key is registered *somewhere*. It does not say on which
I_T nexus. Any conclusion of the form "this key belongs to node X" or "our key is on our own
nexus" drawn from READ KEYS alone is unsupported. **READ FULL STATUS** carries the
transport-identity mapping; use it whenever the question is *whose* registration.

Related, already recorded separately: a PR generation number is not a compare-and-swap condition
on a later PREEMPT AND ABORT, and a PR snapshot is evidence only about the generation it was
taken at.

## 2. "A mounted node lost its own registration" has four explanations

Observing `P305-RESV-SELF-GONE-INSPECT` on a live, mounted node does **not** by itself mean a
fence aimed at a dead predecessor aliased onto the live successor. It is equally consistent with:

- a legitimate fence of the currently ACTIVE incarnation, including one triggered by a
  false-positive death determination;
- a stale or wrongly authorised fence unrelated to succession at all;
- an unregister issued on some other path;
- genuine PR-state loss at the target.

Discriminating requires correlating the completed PR OUT itself — issuer, action, RK, SARK,
type/scope, status, sense — against the frozen victim incarnation and key, and against which
incarnation was active on that host at that instant. Without that correlation the four are
indistinguishable, and picking one is a hypothesis wearing a root cause's clothes.

## 3. Three log lines that read as stronger than they are

- **`P302-PR-KEY-RETAINED-FENCE-TARGET` is not proof a fence target exists.** "Retained" means
  the unregister was skipped. If the key was already gone from the target, nothing was retained.
  Retention is a claim about our own action, not about target state; verify against the target.
- **`umount` rc=0 together with `log_shutdown=1` is not a contradiction.** The detach completed
  cleanly; the slice still did not become durably clean. Do not read the zero exit as cleanliness.
- **`holder_key=0x0` under WE-AR is expected**, not evidence of a foreign exclusive holder — an
  all-registrants reservation has no single holder key. Likewise a REGISTER returning RESERVATION
  CONFLICT says only that this nexus did not hold the supplied RK; a locally cached "selected key"
  is not current registration ownership.

## The general shape

Distinguish, and never let one stand in for another: the key we **selected**, a registration we
**observed**, a registration proven to be on **our own nexus**, a **completed fence**, and a
**durable certificate** of that fence. Most of the wrong turns above are one of these silently
substituting for another.
