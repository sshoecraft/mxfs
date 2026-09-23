# A contract is a conditional, and nobody has established its antecedent

Design-consult ruling (Astra, session 82) on
`D-GATE-AND-SELF-SUCCESSION-KINDS-CERTIFY-FROM-ADMISSION-WITH-NO-RETIREMENT-BASIS`,
asked while verifying the fix the previous ruling
(`fence-gate-and-self-succession-retirement-basis.md`) produced.

It **corrects that ruling and the 0.89.13 package**, so read this one second and
let it win where they differ.

## What the question was

Refusing kind 19 (self succession) left its own case falling through to kind 20
(the sole-survivor exclusive-write gate), which certifies from the same absent
key. I proposed discriminating the observed transition three ways from the
durable PR ledger — no successor record, a successor registered under a
different boot, a successor registered under the same boot — and refusing only
the last.

## The ruling in one line

> A matching contract supplies a **conditional** guarantee. It does not
> establish that the transition covered by that guarantee occurred.

The shipped clause — *for this LUN, every command the target accepted from a
**lost nexus** completed or aborted, effects ordered, before that nexus's
registration disappears* — is an implication. Applying it requires establishing
its antecedent: that **this** registration disappeared **because that nexus was
lost**. Nothing an initiator can see establishes that.

| observed | retirement under the shipped loss clause |
|---|---|
| same-boot MXFS replacement | UNPROVEN |
| different-boot MXFS replacement | UNPROVEN |
| no MXFS successor record at all | UNPROVEN |

Refusing the same-boot case closes the concrete bypass and is necessary. It is
**not sufficient**, and the other two branches were unsupported inferences.

## Why a different boot id proves nothing about the target

The observations establish that MXFS associated two registrations with different
boot identifiers and that a durable record says this host deliberately replaced
the predecessor's key. They do not establish which target-side nexus carried the
predecessor's accepted commands, that the target recognised that nexus as lost,
that the disappearance was the clause's covered transition, or that retirement
preceded it.

Defeaters, all live on this rig or a customer's: kexec (no orderly
target-observed teardown); an initiator that outlives the restarted component
(HBA, firmware initiator, hypervisor, another service); a shared or cloned
`host_uuid`, which breaks the link between the successor's boot transition and
the predecessor's initiator lifetime — host identity uniqueness has to be an
enforced assumption, not a hope; and a module reload under a genuinely per-boot
id, which belongs in the same-boot bucket and produces no cross-boot evidence at
all.

**An iSCSI connection, an iSCSI session, a SCSI I_T nexus and an MXFS boot
identity are four different identifiers with four different lifetimes.** A host
lifetime boundary is not a target-side ordering witness.

## Why "no successor record" proves nothing either

```
no MXFS successor record
    => nobody replaced or removed the registration
    => the registration disappeared through nexus loss
```

is invalid. An administrator, an ordinary PREEMPT, a CLEAR, another
registration operation, or target behaviour outside the qualified transition all
defeat it. Two further holes:

- **A PR-table mutation and an on-LUN ledger write are not atomic.** A crash
  between them leaves an MXFS replacement with no durable successor record —
  exactly the evidence the gate would read as "nobody replaced it". A
  write-ahead protocol closes that one conservatively; it does not close the
  others.
- **The gate does not freeze the PR table.** PR management commands remain
  possible while ordinary writes are excluded, so "I hold Write Exclusive and my
  scan found nothing" is not a stable, comprehensive history of registration
  changes.

## What PR commands can and cannot establish

PR IN supplies registration and reservation state, never a retirement history:
READ FULL STATUS and the PR generation correlate observations, they do not say
why a registration vanished or whether the commands once associated with it have
retired.

PREEMPT AND ABORT is the one active mechanism, and only when its abort scope can
be shown to cover the victim's whole accepted-command line: the affected nexus
set identified correctly, all relevant commands covered including other paths,
the operation completed, and the effects ordered before recovery proceeds. In
the absent-key case none of that is available — naming an absent key does not
reach its old tasks, aborting the successor's registration does not necessarily
cover the predecessor's, and removing every visible competing registration does
not necessarily reach tasks whose registration association is already gone.

**With these observations and this contract there is no positive witness for the
covered transition, so the gate must refuse.** Waiting longer, re-reading the
table, or watching more heartbeat silence does not fill the gap.

The honest ways forward are: qualify a **stronger** contract that covers the
transitions actually observed; introduce an independently verifiable retirement
operation with sufficient scope; preserve enough identity and ordering to
perform a correctly scoped abort **before** the association is lost; or leave
these cases unsupported.

## Where the check belongs

Not "kind 20 also looks for a same-boot successor". That is a regression guard.
The architectural defect is that **a failed retirement proof falls through into a
path that certifies without one**. Every kind must pass one obligation:

```
certificate = valid admission/exclusion proof
          AND valid retirement proof for this exact victim command line
```

built from an immutable, victim-scoped evidence object — subject (LUN identity,
victim host_uuid, boot id, key, death/fencing epoch), observations (PR snapshot
identity and generation, the successor witness if any and its boot relationship)
and a retirement field that is either `UNPROVEN` or a typed, validated proof
carrying its basis and scope. **The certificate constructor rejects `UNPROVEN`,
whatever classification path reached it.**

Two qualifications on that:

- **Do not record "this was not nexus loss" unless that was proved.** A
  same-boot replacement witness proves an MXFS replacement happened; it does not
  prove no nexus loss happened before, during or after. The conclusion to record
  is "this evidence does not establish the loss clause's premise", and that
  replacement must not be laundered into retirement by a later absence-based
  path.
- **A stronger independent proof may legitimately succeed later.** A path that
  actually performs and validates a sufficiently scoped abort is not clearing a
  prohibition, it is satisfying an obligation. So: no mutable global "bad
  absence" flag another path can clear, and no permanent veto either. A failed
  proof must not silently become NOT_APPLICABLE and vanish — preserve the
  witness and the reason the attempted basis was insufficient.

The same central check covers kinds 20 **and 21**. Fixing one moves the bypass.

## Observation identifiers are not claims

```
NO_MXFS_SUCCESSOR_OBSERVED
MXFS_REPLACEMENT_SAME_BOOT
MXFS_REPLACEMENT_DIFFERENT_BOOT
```

None of these is, by itself, a valid retirement claim under the present
contract. Record the observed transition **separately** from the retirement
claim. For a replacement observation, keep or immutably reference the exact
ledger witness: predecessor identity, successor key and boot id, record identity
and version.

## Durable provenance, because a log line is not enough

A takeover prover, a rejoining node and an offline checker all accept a
certificate they did not mint, and today they accept it on `fence_kind` alone.
The durable object must let a reader determine what retirement guarantee the
issuer relied on, which precise claim it asserted, whether that guarantee
applied to this LUN and this victim, what evidence satisfied its premises, and
which proof semantics were in force. Inline or by immutable durable reference —
the requirement is unambiguous meaning and applicability, not a byte layout.

Minimum logical contents of a versioned retirement-proof block:

| content | purpose |
|---|---|
| proof format / semantic version | separates corrected rules from the rules that produced the defect |
| retirement basis enum | qualified contract vs a supported abort-operation basis |
| versioned claim identifier | the exact proposition asserted, not a human-readable label |
| qualification identity | contract id/version or a digest of the exact qualified statement and its applicability conditions |
| target/LUN identity at issuance | binds the qualification to the matched vendor/product/firmware/designator tuple |
| victim identity and epoch | host uuid, boot id, key and the death/fencing record — a key alone is not enough against reuse |
| typed witness payload or immutable reference | the evidence for that claim's premises and scope |
| binding to the certificate and authority epoch | stops a retirement proof for one victim/LUN/attempt being read against another descriptor |

Publication rules that go with it: publish descriptor and payload atomically
under the existing crash-consistency mechanism with integrity checking; retain
referenced objects as long as certificates can be accepted; **reject unknown
mandatory proof versions, bases or claims**; do not retrofit existing kind-20/21
descriptors by attaching `basis=qualified-contract` — missing proof must be
freshly established; treat the PR generation as correlation data, never a
retirement timestamp or a unique lifetime id; and keep **historical retirement**
distinct from **current exclusion** — a certificate recording that a predecessor
was retired does not prove the Write Exclusive reservation still stands when a
later reader acts.

## The shortcuts that would recreate this defect

1. "different boot id" ⇒ "covered target-side nexus loss".
2. "no successor record" ⇒ "loss was the only possible removal cause".
3. "Write Exclusive plus a matching contract" ⇒ "retirement", without
   establishing the contract's premise.
4. A new trigger name or a durable basis label standing in for missing evidence.
5. Fixing kind 20 while kind 21 keeps the same unsupported boot-boundary
   inference.

Under the current support contract these observations justify logging **distinct
reasons for unproven retirement**, not issuing distinct successful certificates.
