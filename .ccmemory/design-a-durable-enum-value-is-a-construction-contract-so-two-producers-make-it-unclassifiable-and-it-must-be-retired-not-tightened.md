---
name: design-a-durable-enum-value-is-a-construction-contract-so-two-producers-make-it-unclassifiable-and-it-must-be-retired-not-tightened
description: DESIGN (Astra s83, 0.89.16): a fence kind on disk identifies a construction contract; tightening its meaning cannot repair instances already written.
metadata:
  type: project
tags: [fencing, on-disk-format, design-ruling, proof-profile]
---

# A durable enum value is a construction contract, not a label

Design-consult ruling (Astra, session 83), banked at
`docs/rulings/fence-certificate-proof-profiles-and-legacy-revocation.md`.
The question was whether a fence certificate needs a new on-disk retirement-proof
block. The answer generalises well beyond fencing.

## The rule

> The requirement is durable, unambiguous identification of a still-supported
> proof contract — not necessarily a separate proof block. A versioned kind can
> encode that contract. But **tightening the meaning of an existing,
> historically overloaded value does not repair its durable instances.** You
> must distinguish new records from ambiguous old ones, or refuse the entire
> ambiguous class.

So a value stored on disk identifies **which code, under which rules, was
allowed to write it**. Two consequences:

- **Never widen or reassign a value's meaning.** If its rules turn out unsound,
  disable *consumption* of that value. If the rules change incompatibly,
  allocate a new one. "Make today's value mean something stricter from now on"
  silently reclassifies every record already written.
- **If two producers can write the same value under different contracts, the
  value is unclassifiable and must be RETIRED** — a fresh code point for the
  sound contract, the old one refused at every reader. This is what happened to
  MXFS fence kind 16: the fence path wrote it after a completed PREEMPT AND
  ABORT, and the bootstrap-owner takeover wrote the *same* value after reading
  its own PR ledger with no operation run at all.

## How to find out whether you have this bug

Do not ask "is the producer correct now?" Ask **"how many producers can write
this value, and did every one of them follow the contract a reader will assume?"**
Enumerate the writers, not the readers. The MXFS counterexample was found by
grepping every assignment of the constant, not by reading the path that looked
relevant.

## The reader rule that falls out

> A reader may authorise an irreversible action only when it can classify the
> record into an explicitly supported, still-sound contract, validate that
> contract's required evidence and bindings, and establish that it authorises
> **this** operation under the applicable authority history. Otherwise it must
> refuse.

Refuse unknown values, revoked contracts, ambiguous historical encodings,
missing evidence and wrong bindings — bounded and diagnostic, never falling
through to a weaker predicate or to another reader that only checks the value.
**"An older build wrote it" is not evidence that the older build was right**,
and *"the value was never rejected" is not a whitelist criterion* — "every
reachable issuance in this durable class satisfies a still-supported contract"
is.

**Mint support and consume support are separate.** A contract may stop being
minted and still be consumed while it remains sound; readers need its
validator, not its producer. The compatibility boundary is contract identity,
not "same build" or "any rule changed".

## Before concluding "no format change needed"

Check that the record actually carries the BINDINGS the contract needs. A key
must not ambiguously identify two incarnations of a subject; an actor's epoch
is not the subject's epoch; a timestamp or a generation counter is not an
operation witness; the proof must cover the actual object and the actual
operation; and an authority transition needs a defined validation rule rather
than acceptance of any historical term. If a needed binding cannot be
expressed, more durable information is required however honest the value space
becomes.

What a richer record buys is **revocation granularity**: with only a coarse
identifier, the next discovery forces revoking the whole class because the
affected records cannot be told from the unaffected ones.
