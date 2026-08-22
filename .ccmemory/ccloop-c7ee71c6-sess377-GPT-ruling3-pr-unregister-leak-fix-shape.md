---
name: ccloop-c7ee71c6-sess377-GPT-ruling3-pr-unregister-leak-fix-shape
description: sess377 RULE-5 ruling for D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377: symmetric all-nexus unregister + mandatory READ KEYS verification + fail-closed;…
metadata:
  type: project
tags: [rule5, gpt-ruling, scsipr, fencing, defect-377]
---

«RULE-5 RULING — clean-unmount PR registration leak (sess377)»

Defect: D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377. Consult 4 of sess377,
gpt-5.6-sol.

## The distinction the ruling insists on

- The SYMMETRIC UNREGISTER is the corrective MECHANISM.
- READ-BACK VERIFICATION is the POSTCONDITION CHECK.
- NEITHER is a complete safety fix unless a failed verification has a defined
  FAIL-CLOSED outcome. "Verify and log" is not enough: it converts a silent
  failure into a detectable one without restoring the fencing invariant.

THE LOAD-BEARING INVARIANT:
> Once MXFS declares an incarnation's storage authority retired, no
> registration bearing that incarnation's PR key may remain.
Membership departure and PR authority retirement must be coupled by either
successful verification or an authorized fail-closed recovery action.

## Approved fix shape (9 items)

1. Stop any future registration/replay of the departing key — serialize
   against path addition, multipath recovery, userspace multipathd key replay,
   and any delayed registration work.
2. Change unregister to a genuine ATTEMPT-ALL-NEXUSES operation, preferably
   through a corrected dm abstraction rather than path-walking inside the
   filesystem (that crosses abstraction boundaries and races dm topology). The
   natural symmetric operation is REGISTER AND IGNORE EXISTING KEY with
   service-action key zero — PROVIDED the dm implementation visits all paths
   and does not fail early. Do NOT assume dm's registration rollback/fallback
   gives that contract for new_key == 0; verify that exact case.
3. REMOVE the unconditional RESERVATION_CONFLICT -> success mapping.
4. Perform complete READ KEYS (or better READ FULL STATUS, which identifies the
   registered I_T nexuses) verification.
5. Retry within a REAL bounded deadline.
6. Treat failed or incomplete verification as STORAGE AUTHORITY NOT RETIRED.
7. On failure invoke local isolation / self-fencing, or hand a certified
   recovery descriptor to the existing fencing protocol.
8. Permit survivor cleanup ONLY with normal fencing authority.
9. Keep PER-INCARNATION keys but widen from a 32-bit node_id to a
   collision-resistant 64-bit incarnation identifier.

## The result mapping (directly implementable)

| unregister result | read-back | outcome |
|---|---|---|
| success  | key absent  | success |
| success  | key present | failure / partial cleanup |
| conflict | key absent  | success: already gone |
| conflict | key present | failure / partial cleanup |
| any      | read-back failed/incomplete | UNKNOWN = failure |

The only valid reading of a conflict is "the requested state was NOT
established by this command; inspect global state" — never "the key is
globally absent". A conflict from ONE nexus can mean: that nexus no longer has
the key; another node preempted it; a previous unregister succeeded there; the
key is still registered on another multipath nexus; or the aggregate operation
stopped before visiting the remaining paths. A read-back is MANDATORY unless a
future operation carries a strong all-nexus success contract — and even then
retaining it at a fencing boundary is reasonable.

## Verification details that matter

- Handle READ KEYS response truncation using the returned ADDITIONAL LENGTH.
- The PR generation can change while reading; retry if it does.
- An incomplete or failed READ KEYS NEVER means absence.
- Do not BUG_ON because storage is sick — make it an explicit fencing/authority
  failure, not a generic kernel assertion.

## Q2 — is READ KEYS safe at the end of xfs_fs_put_super?

Yes in principle, provided MXFS still holds a valid bdev reference, the queue
and dm target are usable, no teardown lock is held that storage completion or
dm path recovery needs, the PR op bypasses XFS's shutdown rejection and goes
straight to the block PR interface, and nothing can re-register the key after
verification. PR IN issues no cache flush, changes no reservation state and
needs no write authority, so it cannot recreate the earlier Synchronize-Cache
reservation-conflict problem that forced this late ordering.

THE HAZARD IS LIVENESS, NOT PR SEMANTICS. A synchronous PR request can block
far longer than a source-level retry loop suggests: dm-multipath
queue_if_no_path / large no_path_retry, SCSI command timeouts and error-handler
recovery, path failover, target stalls, uninterruptible block waits. Use BOTH a
bounded attempt count AND an absolute wall-clock deadline enforced by lower
layers that do not queue indefinitely — a loop deadline is useless if one call
can block forever. Tens of seconds, or one normal SCSI recovery interval, as
CLUSTER POLICY rather than accidental exponential backoff.

When the bound is hit the state is UNKNOWN, not "gone". put_super cannot
usefully roll back, so the design needs to separate "local filesystem teardown
complete" from "storage write authority retired". Acceptable fail-closed
outcomes: locally isolate or tear down every initiator session that could use
the registration; self-fence/reboot under cluster policy; publish a durable
recovery descriptor before departure transferring responsibility to an
authorized survivor; refuse to certify the incarnation as safely departed.
Merely logging and letting the node keep running with raw LUN access is NOT a
safety outcome — a stale registration on a LIVE initiator nexus can authorize
non-filesystem I/O even though MXFS is unmounted.

SUGGESTED TWO-PHASE DEPARTURE: (1) earlier, publish a "storage authority
retirement pending" recovery record; (2) do all filesystem writes, flushes and
DLM shutdown in the existing safe order; (3) at the final point unregister and
verify; (4) mark the record complete if absent; (5) if present/unknown leave
the record for an authorized recovery/fencing path and apply the local
fail-closed policy. This avoids trying to rejoin the DLM or resurrect a
superblock after late cleanup fails.

## Q4 — survivor reaping of orphan registrations

NOT merely because a key is absent from the survivor's membership view.
Removing another nexus's registration is a PREEMPT, i.e. a fence. An "unknown"
key could be a live node missing from a stale/partitioned view, a joining
incarnation not yet visible, a recovery in progress, a node of another cluster
through misconfiguration, or an old incarnation whose mapping was discarded. A
casual garbage collector is a second, less-controlled fencing implementation.

A reaper needs, at minimum: a committed fresh membership/recovery term; the
same quorum/authority MXFS already requires for fencing; a DURABLE mapping from
PR key to cluster, host and incarnation; proof the specific incarnation is
excluded or that its retirement was handed off; serialization against
join/key allocation so the key cannot be reassigned while cleanup is pending; a
fence/recovery certificate covering the LUN and key; and verification after the
PREEMPT that the key is absent. An unrecognized key with no trustworthy mapping
should QUARANTINE/ALERT, not be preempted.

Put orphan cleanup inside the existing fencing/recovery state machine as
"complete storage revocation for certified-dead incarnation X", never as
"periodically remove keys I do not recognize". This also covers the case where
a path was unavailable during local unmount: REGISTER-based deregistration can
only act as the corresponding I_T nexus, so removing an inaccessible nexus's
surviving registration may require an authorized PREEMPT from another nexus.

## Q5 — per-incarnation vs stable per-host keys

KEEP PER-INCARNATION. A stable host key is dangerous here: an old and a newly
booted incarnation can carry the same value; READ KEYS cannot tell them apart;
a PREEMPT meant for the old one removes the NEW one; a fence certificate for
the old incarnation effectively authorizes action against the current one; and
a new registration can make an old leak look accounted for while two nexuses
stay registered. A stable host key is safe only if the HOST is the fencing unit
and the protocol forbids a new incarnation using the LUN until every old
session and registration is proven dead — far more restrictive than MXFS's
incarnation-based membership.

Use a stable host identity for administration and fencing-device selection, and
a distinct globally unique mount/boot/incarnation identifier for the PR key.
Use the FULL 64 bits: a 32-bit node_id is weak for a value that must stay
unambiguous across failures and historical leaks. Options: a quorum-assigned
monotonically unique 64-bit incarnation number; a random nonzero 64-bit value
collision-checked against membership and observed PR keys; or a 64-bit digest
of {cluster UUID, stable host id, boot id, mount/incarnation counter}. Keep a
durable mapping "PR key -> cluster UUID, host id, incarnation id, membership
term" in the membership/recovery record: the key is an opaque identifier, not a
security credential.
