---
name: ccloop-c7ee71c6-sess381-GPT-ruling-we-ar-fencing-lifetime
description: sess381 RULE-5 ruling: switch to WE-AR (all registrants) behind a proto-gen bump; encode the command-submission boundary, not the reason; and the reg…
metadata:
  type: project
tags: [sess381, rule5, gpt-ruling, scsipr, we-ar, fencing, 381]
---

# sess381 RULE-5 ruling — WE-AR, and the fencing state machine

Consulted with the full measured chain for
`D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381` and
`D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381`. Verdict: the root chain is
correct, **F1 (WE-AR) is the right primary lever**, provided it is protocol-gated.

## Confirmed (two of these I had already proven on the rig)

- **(a)** WE-AR survives removal of any single registration — via REGISTER-sark-0,
  via PREEMPT, via any other removal — while at least one registrant remains.
  *(Independently MEASURED on this SCST target before the consult returned.)*
- **(c)** RESERVE from an already-registered node when a matching-scope/type WE-AR
  reservation exists completes **GOOD** (holder-issued RESERVE with matching scope
  and type is a successful no-op; under an all-registrants type every registrant is
  a holder). *(Also MEASURED: rc=0 from a second nexus.)*
- **(e)** Prefer WE-AR over EX_AC_AR: EX_AC_AR also blocks **reads** by
  non-registrants, which buys no write-safety and creates outages during
  pre-registration metadata reads, path failover, and diagnostics. WE-AR is the
  least restrictive type with the required property.
- **(b)** PREEMPT AND ABORT under WE-AR removes the victim's registrations, aborts
  its task set, and leaves the reservation in force because the prover is still a
  registrant. No "transfer to A" concept is needed — A was already a holder.

## New hazards it raised

- **`SARK == own key` is not a self-fence.** The issuing nexus's own registration is
  protected from its own PREEMPT, while *other* registrations carrying the same key
  are removed. With MXFS's one-key-across-two-nexuses scheme this silently kills
  sibling paths without fencing the issuer. **Reject `victim_key == own_key` before
  issuing.** Ties to `D-PR-KEY-32BIT-NODE-ID-COLLISION-RISK-377`.
- **Under WE-AR there is no single holder key** — READ RESERVATION returns 0.
  *(MEASURED: `Key=0x0`.)* Audit every parser, log line, certificate field and
  "one holder" assumption, not just the `resv.type ==` comparisons.
- **Stop reading RESERVATION CONFLICT as success.** Under WE-AR a conflict from a
  correctly-registered requester means wrong type/scope or a lost registration.
  Read back and classify: GOOD / conflict / transport-timeout (outcome UNKNOWN,
  do not claim the reservation exists) / unsupported / unit attention.
- **The admission gate needs a bootstrap branch.** "Refuse if no reservation was
  already present" makes the first mount of an empty filesystem impossible. Model:
  no reservation **and** no registrations = bootstrap, establish it; correct WE-AR
  present = join; registrations present but reservation absent = **degraded
  invariant**, alert and repair under serialization; wrong type/scope = fail closed;
  incomplete PR view = do not admit. Log the pre-action state *and* the final state.
- **Do not PRIN from 32 heartbeat threads.** One elected PR-health maintainer, plus
  event-triggered checks (mount, unmount anomaly, target reset / unit attention,
  and immediately before fencing), plus a slow jittered audit. The fencing path must
  verify/establish WE-AR itself rather than waiting on a periodic thread.
- **Re-reserving is not self-heal.** "WE-AR absent while registrants live" is a
  high-severity safety event: restoring it fixes future exclusion but does not prove
  the unprotected interval was harmless.

## The fencing state machine (defect #2)

Replace "proved / attempted" with a phase enum encoding **the command-submission
boundary, not the reason**:

1. `PRECOMMAND_RETRYABLE` — no state-changing command submitted. Safe to retry.
2. `COMMAND_MAY_HAVE_BEEN_SUBMITTED` — issued but outcome unobserved (timeout, path
   failure, reset). **Must not** be labelled "attempted nothing".
3. `EXCLUSION_VERIFIED` — post-command verification passed.
4. `TERMINAL_INCOMPATIBLE`.

Key warning: **do not derive retryability from the kind for new records.** A future
refactor could detect reservation loss *after* submission, and the reason would lie.
Encode the phase.

Keep the durable intent (the slice still may not be replayed) but make the guard
re-openable under a fresh term. Two provers stay safe because guard updates are
term/epoch CAS'd and only the current lease owner may advance them; a no-command
precondition failure changes no target state and cannot un-exclude anyone.

**`GOOD` status is not a certificate.** Before certifying, still holding the fencing
lease: re-read and assert victim key absent from a *complete* key view, reservation
still held and still the right type, own registration present, PR generation
consistent, all of the victim's nexuses covered.

**Repairing already-bricked guards:** re-open when guard version + stage + kind
unambiguously mean "returned before P&A" for every binary that could have written
the record, the old term is dead, and no later certified result exists. Then: victim
key **present** → P&A and verify (the clean case, and the one this rig is in); victim
key **absent** → do **not** fabricate a certificate, since absence is equally
consistent with a clean unregister or a plain PREEMPT without ABORT.

## Rollout — the part I must not skip

A mixed cluster is unsafe: old binaries hard-require `resv.type == WE_RO` in three
places (`dlm/scsipr.c:427` fence, `:661` admission, `:740` certificate verify) and
would classify WE-AR as NO_RESERVATION. Sequence: ship a bridge version that reads
both types but still creates WE-RO; upgrade everyone; drain non-holders first and
the WE-RO holder **last** (so the reservation survives until the cluster is empty);
bump `MXFS_PROTO_GEN` while offline; first new mount establishes WE-AR; reject old
binaries on the new generation. A live conversion has an unprotected RELEASE→RESERVE
gap — exactly the class of interval the design exists to prevent — so it is not the
initial fix.

## The biggest thing beyond my proposal

**Registration happens before admission.** A node gets SCSI write access the moment
it registers, before the on-disk guard has rejected it. PREEMPT is *not sticky*: a
preempted node can simply re-register its key and reacquire write access during
exactly the recovery interval the guard protects. Needs: registration/admission and
fencing serialized under a cluster-wide lease; a key/incarnation may not register
while its old slot is under recovery; no filesystem write I/O before admission
completes. Same protocol-generation change.
