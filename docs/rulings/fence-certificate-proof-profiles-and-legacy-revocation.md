# Proof profiles, and why an honest kind space is enough but a tightened one is not

Design-consult ruling (Astra, session 83) on
`D-FENCE-CERTIFICATE-CARRIES-NO-DURABLE-PROOF-PROVENANCE-SO-A-CORRECTED-BUILD-HONOURS-ONE-MINTED-UNDER-REJECTED-RULES`,
and on the two producer defects that turn out to be the same subject: the
bootstrap-owner takeover that mints a fence kind from ledger state, and the
operator's single-node assertion that certifies replay with no retirement basis.

It supersedes the earlier prescription — "design a versioned retirement-proof
block and change the on-disk format" — by **narrowing** it.

## The ruling

> The requirement is durable, unambiguous identification of a still-supported
> proof contract — not necessarily a separate retirement-proof block. A
> versioned kind can encode that contract.
>
> But tightening the meaning of an existing, historically overloaded kind does
> not repair its durable instances. You must distinguish new certificates from
> ambiguous old ones, or refuse the entire ambiguous class.

A separate proof object is **one implementation, not an inherent requirement**.
What is inherent: **readers cannot silently reinterpret old evidence under new
rules.**

And a second, independent point, because it was the question that produced the
ruling: *"kind 19 must be refused at every authorising reader now. You do not
need to prove that every possible instance of 19 was unsound before refusing
it. You need a supported, sound interpretation before accepting it. The
bootstrap producer is another reason not to trust that kind, not a reason to
retain acceptance."*

## What a fence kind has to become

An immutable, **versioned proof-profile identifier**. A profile identifies more
than a broad basis such as "a target operation ran": it identifies which
operation and which completion conditions count, which victim and exclusion
domain it covers, which qualification assumptions apply, what durable fields
bind it to the recovery being authorised, and how its validity survives — or
does not survive — an authority change.

Two rules follow, and they are what makes the identifier worth anything:

- **A profile's meaning is never widened or reassigned.** If its rules are
  found unsound, disable *consumption* of that profile. If the rules change
  incompatibly, allocate another profile. Do not make today's kind mean
  something new tomorrow — allocate a previously unused code point.
- **This is an on-disk compatibility change even when the descriptor stays 120
  bytes.** The bytes did not move; what they mean did.

Acceptance then has this shape, and the table selects a validator rather than
being the answer:

```text
profile = classify(record_family, format_version, kind)
require profile is recognised and enabled for consumption
require verify_certificate(profile, record, recovery_context)
```

At minting, the constructor must require an **operation-derived, scope-bound**
result that only the completed-operation path can produce. Ledger statuses,
membership conclusions and module parameters must not be able to manufacture
it, and constructor exemptions are removed.

At consumption, a compact kind-only profile is an **issuer attestation under a
fixed construction contract** — the reader is not reconstructing the SCSI
completion from the kind. That is acceptable under a trusted-writer model only
if the durable discriminator unambiguously selects the construction contract,
that contract is still sound, the remaining durable bindings suffice, and
**every** producer of that discriminator was required to follow it. Note that
merely adding a `basis` field would still be an issuer assertion; it is not
automatically stronger evidence than the kind.

## The decisive limitation is historical ambiguity

The counterexample that produced this ruling: a bootstrap-owner takeover mints
`PREEMPT_ABORT_DONE` **from ledger state, with no operation run in that
attempt** — the victim's key is absent from the target but the node's own PR
ledger says FENCED (or RETIRED), and it proceeds. It mints
`SELF_SUCCESSION_DONE` from a boot boundary the same way.

That establishes that **the global kind 16 is not a sound, unique proof-profile
identifier**. It does not by itself establish that every *recovery-descriptor*
instance of 16 is contaminated — the record family is also durable information
— but claiming that exception requires an audit of historical producers and
propagation paths, not just today's constructor. If bootstrap evidence could
ever be copied, translated or promoted into a descriptor 16, the exception
fails. **Retiring legacy 16 globally and using a fresh kind is the simplest
conservative implementation**, and it is the one to take unless the audit is
done.

| durable class | consumption |
|---|---|
| 17 under the assertion-only rules | refuse replay authority |
| 19 | refuse at all three readers, and any others |
| 20, 21 | continue refusing |
| bootstrap-record 16 reachable from FENCED/RETIRED ledger state | refuse |
| recovery-descriptor 16 | accept only if its entire historical producer/import path is demonstrably a sound, unambiguous completed-operation profile |
| unclassified or unresolved class | refuse |
| a fresh versioned completed-operation profile | accept only after its full validator succeeds |

**Check the bindings before concluding "no layout change needed."** The fence
fields alone do not establish a durable victim-epoch or target/LUN binding. A
PR key must not ambiguously identify different victim incarnations; a prover
epoch is not a victim epoch; a timestamp or PR generation is not an operation
witness; a proof must cover the actual target/LUN and recovery subject; and an
authority transition needs a defined validation rule rather than acceptance of
any historical term. If the record cannot express an indispensable binding,
that requires more durable information however honest the kind space becomes.

Two bases do not force a future layout change — allocate two versioned kinds.
What a richer block buys is **revocation granularity**: with only a coarse
identifier, a future discovery forces rejecting the whole profile because the
affected certificates cannot be distinguished from the unaffected ones. It
cannot guarantee that every future rule change is decidable from evidence
already recorded.

One nuance worth keeping: *"no operation in this attempt" is not inherently
disqualifying.* A properly validated durable certificate of an EARLIER
operation may be reusable under its scope and authority rules. The current
FENCED/RETIRED ledger labels are not such a certificate.

## If extra proof bytes do turn out to be needed

Prefer a **versioned root carrying a bound reference** plus an **immutable
proof object** readable before replay is authorised, published in this order:
construct the object with its profile, scope, qualification and certificate
binding; write it to its final immutable location; make it durable under the
required ordering and flush/FUA guarantees; atomically publish the root that
references it; reclaim superseded objects only when no valid root or concurrent
reader can reach them. The invariant is not that all writes are atomic
together — it is that **an authorising root cannot become durable before its
complete proof is durable**. Crash outcomes: before root publication the object
is unreferenced and confers nothing; after publication the referenced proof
must validate; a torn root, a missing object, a bad length, a wrong identity or
a mismatched binding all refuse.

Caveats that matter here: an external object does not solve "no spare bytes" by
magic — its reference still needs somewhere durable to live, so this is a new
root layout or an already-defined uniquely-bound locator; never invent an
implicit locator from a timestamp or a reusable ledger slot; a CRC is not
crash-atomic publication, and falling back to an older slot is permissible only
if that slot independently passes the current authority and proof checks; and
the object must not require the replay it authorises in order to be located or
read. An adjacent-region carve can be correct too, but it is an explicit layout
revision needing updated tools, ownership rules and the same crash protocol —
it is not preferable merely because the bytes are nearby.

**For this defect alone, do not change the layout just to store a redundant
basis enum.** First determine whether a fresh compact profile plus the existing
bindings suffice.

Existing certificates with no block split in two. Where a legacy encoding is
*itself* a sufficient compact proof profile — an audited `(recovery
descriptor, legacy format, kind 16)` class might qualify — it may be supported
explicitly, and that is recognising an unambiguous encoding whose contract
remains sound, not retrofitting a proof. Where the old encoding cannot
distinguish sound from unsound issuance, refuse it: no block and no migration
utility recovers a missing historical fact by copying the old kind, a ledger
status or a log conclusion. **"The kind was never rejected" is not a whitelist
criterion; "every reachable issuance in this durable class satisfies a
still-supported contract" is.** A stranded pending recovery has two options —
obtain a new, independently supported proof and issue a new certificate, or
stay blocked. Availability does not supply the missing evidence.

## The general reader rule

> A reader may authorise replay only when it can classify the certificate into
> an explicitly supported, still-sound proof profile, validate that profile's
> required evidence and bindings, and establish that it authorises **this**
> recovery under the applicable authority history. Otherwise it must refuse.

Refuse unknown kinds and claim versions, known-revoked profiles, ambiguous
historical encodings, missing proof data, unsupported qualification
assumptions, and incorrect subject/target/epoch/certificate bindings. Refusal
is bounded and diagnostic, and must not fall through to a weaker predicate, a
membership assumption, an operator exemption, or another reader that merely
checks the kind.

This does not make every code change incompatible, because **mint support and
consume support are separate**. A profile may stop being minted and still be
consumed while it remains sound; readers need its validator, not its producer.
An existing profile stays accepted when an implementation change preserves the
same contract, when a newer rule is an equivalent or conservatively compatible
formulation, or when the recorded evidence satisfies a still-supported
validator. An incompatible rule change needs a new profile; a rejected safety
assumption needs revocation of the affected class — the identifiable subset if
durable information identifies it, the whole indistinguishable class if not.
The boundary is **proof-contract compatibility**, not "same build" or "any rule
changed".

## Implementation order

**First — close authority at the readers and disable unsupported issuance.**
Before designing any new object format. Build the common
classification/validation interface and route every acceptance through it:
recovery-descriptor consumption, bootstrap-owner acceptance, the mount-time
recovery check, takeover and rejoin paths, and the offline checker's
classification. Delete every authorisation decision equivalent to
`kind == 16 || kind == 19`. In the same safety release: refuse 19 everywhere;
refuse assertion-only 17; keep refusing 20 and 21; refuse contaminated legacy
bootstrap 16; refuse unresolved legacy classes; disable bootstrap issuance from
FENCED/RETIRED ledger status and from boot boundaries; and remove the
single-node constructor exemption. The operator parameter may select an
operating mode; it may not create a retirement witness. If the work must be
serial, do the reader refusals, then the bootstrap producer, then the singleton
exemption — **but never ship an intermediate state carrying an alternative
authorising bypass.**

**Second — establish the sound mint/consume contract.** Add the fresh
completed-operation profile and its typed constructor, creatable only by the
qualified completed-operation path, with its result bound to the victim, the
exclusion domain and the authority context, and publication authority
re-checked before commit. Bootstrap takeover uses that same path when it
actually establishes the proof, and otherwise refuses; reusing a prior
certificate can come later through the normal validator, and is never "the
ledger says FENCED". This step is what determines the real evidence and binding
requirements, and doing it here stops the storage design from being built
around the defective producers.

**Third — change the representation only where those requirements demand it.**
If the existing fields suffice, keep the layout and use versioned profiles. If
they do not, build the versioned root/object design and its crash protocol —
once, for both producer defects, sharing one constructor and one validator.

**Fourth — enforce upgrade compatibility.** A corrected reader does not repair
an older node that still accepts rejected certificates. Verify that old
binaries refuse fresh profiles, and prevent old authorising implementations
from participating after the cutover, through an incompatible-feature mechanism
or an enforceable all-reader cutover. If neither can be enforced, a
compatibility gate is needed even when the proof fits the current layout. An
"upgraded deployment" assertion is not a substitute for excluding an old
write-capable implementation.

## The rig arms this needs

Keep the existing refusal tests, and add:

1. **Real legacy issuance** — use the old bootstrap path to write kind 16 from
   both FENCED and RETIRED ledger state; corrected readers must refuse those
   records with no replay writes and no relabelling.
2. **An all-reader matrix** — 17, 19, 20, 21, contaminated 16, unknown kinds
   and unknown versions, through every listed consumer.
3. **A mint barrier** — ledger state, a boot boundary and the single-node
   parameter cannot produce the fresh profile, and neither can a command
   timeout, an uncertain completion or registration absence.
4. **A positive arm** — a genuinely completed, qualified operation produces the
   fresh profile and the non-minting readers accept it within its valid scope.
5. **Binding failures** — wrong victim incarnation, target/LUN, authority
   context and certificate binding must each fail, even with a recomputed valid
   CRC.
6. **Crash publication**, if an object is used — crash at each durability and
   publication boundary; no root may authorise using a missing, stale or
   substituted proof.
7. **No silent migration** — an ambiguous legacy certificate cannot become
   acceptable by rebooting, taking over, upgrading or copying ledger state.

## How step four is enforced: the generation cutover

Step four asked for an incompatible-feature mechanism *or* an enforceable
all-reader cutover, and said in terms that an "upgraded deployment" assertion
is not a substitute. MXFS already owns the second mechanism, so the decision is
to use it rather than to grow the envelope: **`MXFS_PROTO_GEN` moves 21 → 22**.

### Why a bump and not a new format region

The revocations changed what a durable recovery descriptor *means* — kind 16
retired, kind 17 revoked, kind 23 the only class carrying a declared
retirement basis — while leaving `MXFS_RECOV_DESC_VERSION` at 3 and the
generation at 21. The descriptor's own coexistence argument forbids exactly
that: a reader that predates the change replays first and classifies
afterwards, so per-record fail-closed is no defence. Nothing on the old side
fails closed, because from its point of view nothing changed.

The hazardous direction is not an old node reading a new record. Kind 23 is a
code point it has never heard of, and its `kind == 16 || kind == 19` test
refuses it. The hazardous direction is an old node **joining** beside a
corrected one and **minting** kind 16 from a basis that was retired: the
corrected build refuses that certificate, the old build honours its own, and
replays a peer's slice on a retirement claim nobody ever proved. Refusing the
class at the corrected reader does not repair the node that still mints it.

### What the bump actually enforces

Two independent gates, one for each state an old node can be in.

- **Not yet mounted.** The exact-match generation gate refuses the mount:
  `cluster_proto_gen != MXFS_PROTO_GEN` → `-EPROTONOSUPPORT`
  (`pal/linux/xfs_super.c`, the C7 gate). It is not bypassable by
  `mxfs.legacy_rw`, which only covers the bit-absent legacy format.
- **Already live.** The generation travels in the heartbeat feature block, so
  a mismatched incarnation already on the LUN is not merely ignored: the
  monitor classifies it `MXFS_HBFEAT_MISMATCH` and fences it (`P-VERGATE …
  live protocol-incompatible member, fencing`, `dlm/disklock.c`), and a joiner
  that meets a live incompatible incumbent withdraws rather than joining
  (`P-VERGATE-JOIN`, `-EPROTO`).

No new on-disk region is required; the generation is stamped by `mkfs_mxfs`
(and by `chk_mxfs --upgrade-protogate` on an existing volume), so the cutover
is an offline re-stamp rather than a format migration.

### What this does not claim

It excludes an old implementation from a filesystem that has been stamped at
generation 22. It says nothing about a volume that was never re-stamped — such
a volume still speaks generation 21 and an old module mounts it exactly as
before. The cutover is the stamp, not the release.
