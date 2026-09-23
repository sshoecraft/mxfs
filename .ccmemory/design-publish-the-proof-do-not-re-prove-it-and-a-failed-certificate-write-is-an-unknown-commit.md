---
name: design-publish-the-proof-do-not-re-prove-it-and-a-failed-certificate-write-is-an-unknown-commit
description: DESIGN (Astra s80 ruling, D-381): retry certificate PUBLICATION not fencing; a failed CAS may have landed; WRITE retirement and PROUT retirement are…
metadata:
  type: project
---

## The ruling (Astra, session 80, on the two remaining halves of D-381)

Three facts must be kept separate, and none implies the others:

1. the victim cannot submit new effective I/O (ADMISSION);
2. the victim's previously admitted I/O has retired (RETIREMENT);
3. the *predecessor prover* cannot cause further conflicting PR side effects.

### Half 1 — a successor that takes over and issues a fresh PREEMPT AND ABORT

- **Two PREEMPT AND ABORTs are not intrinsically dangerous.** Under distinct
  non-reused per-boot keys, one removes the victim's registration and the other
  fails to match. Do not call PREEMPT AND ABORT "idempotent" either — issuer,
  reservation type and parameters matter.
- **My key-reuse argument was wrong as stated.** A delayed command naming the
  old boot's key K1 does not remove a new boot's registration K2. The real gaps
  are: same-boot remount reusing the key, key-derivation collisions, an I_T
  nexus identity not being a boot identity, and already-selected nexuses /
  deferred abort work / reservation effects that a future key lookup does not
  describe.
- **WRITE retirement ≠ PROUT retirement.** "Outstanding data writes from a lost
  nexus cannot reach media" does NOT establish "an accepted PROUT from that
  nexus cannot later change PR state or perform an abort". A contract can cover
  both, but only if it says so — that is a *stronger* contract, not an
  implication. Also: host death does not prove target-side nexus loss, and
  nexus loss does not generally imply PR deregistration.
- **Rejected shortcuts**: "the predecessor's nexus may still be live" (liveness
  is not outstanding-command liveness — a dead nexus can have executable work, a
  live one can be drained) and "the PR generation moved" (not a command
  completion sequence number; unrelated operations advance it, it names no
  operation, and it says nothing about deferred abort effects).
- **Provenance**: one history bit plus an overwritten prover id is insufficient
  across repeated takeovers. Preserve predecessor incarnation/operation
  identities, or enforce a durable retirement watermark.
- **Consequence that widens the problem**: if an old command really can harm a
  returning incarnation, refusing only the successor's second command is not a
  complete fix — the old command already exists, and the hazard must be
  discharged before any replay/rejoin transition that assumes its absence.

### Half 2 — a proved exclusion whose certificate write fails

- **Retry the PUBLICATION, not the fencing.** Retain the completed proof bound
  to an immutable attempt identity (slice/slot incarnation, term, prover
  incarnation, victim incarnation and key, LUN identity) and re-attempt only the
  CAS.
- **A non-`-EEXIST` error is an UNKNOWN COMMIT OUTCOME, not proof of failure.**
  The response can be lost after commitment. Publication must be idempotent and
  must reconcile the actual descriptor; never rewrite FENCING/CERTIFIED from a
  stale in-memory copy. With a genuine version-checked CAS, a successor's
  takeover and the old prover's certificate CAS cannot both win.
- **Read-back is not durability.** Matching bytes in a read may be volatile
  cache; use the metadata layer's durable commit-reconciliation.
- **Blocking is an operational state, not a verdict.** "Replay is unauthorised
  because no valid durable certificate exists" — never "this slice can never be
  certified again". Routes back: the same live prover retries later;
  reconciliation finds the CAS did commit; a later owner obtains an independent
  proof (boot succession, with its own retirement basis). Blocking must be
  conditional on the same attempt identity so a late error handler cannot block
  a slice another thread has certified.
- **Proof decay**: historical retirement does not decay; *admission
  observations do*. "The key was absent at T" is not enduring if that
  incarnation can register again — the admission/rejoin protocol must prevent
  re-entry; repeated reads before the CAS do not close that gap. Own-key
  presence is not a lease proof; victim-key absence is not a retirement proof.

## What 0.89.13 implements from this

Half 2's publication retry: five attempts, doubling backoff from 200 ms (~6 s,
inside a returning peer's 30 s mount barrier), reconciliation supplied by the
disklock primitive itself (it re-reads the descriptor and answers 0 when this
attempt's certificate already stands under our lease, -EEXIST once sealed or
taken over), the honest replacement for the "needs operator action" text, and
two injectors — `dbg_cert_fail_n` (report failed without issuing) and
`dbg_cert_lost` (let it commit and withhold the result). Harness:
`tests/fence_cert_publish.sh`. Half 1 is not implemented yet.
