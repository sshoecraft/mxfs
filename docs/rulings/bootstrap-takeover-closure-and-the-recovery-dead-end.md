# Closing the bootstrap-takeover record, and the recovery dead end it reveals

Design-consult ruling (Astra, session 86, 0.89.19) on
D-BOOTSTRAP-TAKEOVER-MINTS-A-FENCE-KIND-WITH-NO-PROOF.

Three claims were brought as one and have to be separated, because the evidence
for each is different and only the first is nearly in hand:

1. the unsafe producer no longer manufactures fencing authority;
2. every reachable bootstrap takeover route enforces the proof requirements;
3. the supported failure sequence remains recoverable.

The lap proposed in the record — A mounts alone and CLAIMs the bootstrap term,
A is power-cut, B mounts and must take the term over against a key the target
has already purged — is strong evidence for (1) on the slotless path. It is not
evidence for (2). And its expected outcome measures a failure of (3).

## 1. The producer lap, and what makes it vacuous

**Bind the pre-cut state to one owner boot and one term.** The evidence has to
say: a durable, valid bootstrap record reads CLAIMED, term T, owner A1, owner
key KA1; KA1 is registered *on the target*; and A1 neither relinquished that
registration nor advanced the record before the cut. `P-BOOT-CLAIMED` is a
usable trigger but is not by itself proof that the claim committed, and the PR
ledger is not evidence that a target registration exists — reading the ledger
as a target fact is the producer's own mistake and the lap must not repeat it.
Target-facing PR IN evidence for that exact key, before the cut, is what
carries it. Afterwards, before B can touch the record, re-read the durable
record and confirm it still says CLAIMED(T, A1, KA1). The 129 s window makes
the experiment practical; it does not prove where the cut landed.

Also establish that the slices are genuinely dirty in durable metadata rather
than inferring it from "both mounts fsynced", and distinguish A1's key from the
key of A's earlier boot.

**Show B reached the defective decision point**, not some earlier door: B saw
that open term owned by A1; entered bootstrap takeover rather than a clean
mount or ordinary recovery; registered as a contender and satisfied the real
abandon-window rules; took the *slotless* branch; looked up KA1; saw it absent
target-side; and reached `v5_boot_tk_fence_key()`, which returned -ENOKEY at
`P-BOOT-TAKEOVER-FENCE-UNPROVEN`. A refusal that came from a descriptor,
identity, version or eligibility check is a different measurement.

**Capture the predicates the deleted branches would have read.** This is the
condition most easily missed. An absent key does not by itself mean the old
code would have minted anything: if the ledger lookup returned neither FENCED
nor RETIRED and no succession predicate matched, the old code would also have
refused, and the lap would then be exercising the new refusal without ever
reproducing the defect. The counterfactual "the old build would have minted
kind 16 here" is only supported by the recorded predicate values.

For the same reason, one B-takes-over-A lap does not measure the own-nexus
self-succession branch at all. The honest shape of the closure argument is:
the lap measures the antecedent(s) it actually hit; inspection establishes that
the absent-key path now refuses unconditionally whatever those bookkeeping
predicates say; predicate-level regression tests may cover the rest. "This lap
measured all three deleted branches" would be false.

**Assert the absence of AUTHORITY, not the absence of kind 16.** Substituting
some other unsupported class, or a spuriously "proven" one, preserves the
defect exactly. Scoped to newly created authority for fencing A1 or replacing
term T (pre-existing certificates elsewhere on the LUN are not a failure), the
lap must show: no certificate minted even transiently; none durably published
in any certificate-bearing store; no ledger transition representing this
attempt as successful fencing or retirement; no owner-replacement lineage
entry; no reseal or owner/term replacement; no manifest sealed for this
attempt; no execution lease that depends on A1 being fenced; no recovery
descriptor supplying that authority; and no replay or recovery execution under
it. It must also show that no independent valid prior proof was available and
consumed instead — otherwise this is not the "proof unavailable" arm.

Disk inspection after the fact cannot exclude "minted, used, then overwritten",
and a missing log line cannot exclude unlogged publication: enumerate the
minting and publication sites and instrument them, then corroborate with
durable before/after images. "Leaves the record as it stands" means its owner,
term, recovery state and protected contents do not advance — if contender
admission legitimately updates other bookkeeping, say so rather than assert
that no byte moved. Finally require a bounded, clean mount failure: no leaked
recovery work, no stuck teardown, no shutdown, no kernel failure. Preserve the
evidence before anything clears the record.

## 2. The escrowed-slot (K) branch is a separate disposition

Two different scopes are being conflated. Narrow producer closure — those three
branches are gone from the direct-key producer — does not require driving
unrelated code. Whole-record closure — *bootstrap owner replacement requires
sound fencing on every route* — needs the K route driven, or a demonstrated
invariant that makes it unreachable in the supported configuration. The
0.89.17 classifier arms do not establish that a bootstrap route calls the
classifier.

Do not infer the branch from the phase name. "CLAIMED has sealed nothing" is a
hypothesis. The decisive identity is that the record escrowed as K belongs to
the exact boot and key owning the open term — A's earlier pre-outage boot in a
manifest is not that, and neither is a slot with the same node identity under a
different boot or key.

The cheapest two-node schedule is the same lap with the cut moved to the first
genuine protocol point at which A1 still owns an open term, A1's exact boot/key
has the heartbeat representation B will legally escrow as K, that
representation is durable, and the term has not reached RECOVERY_COMPLETE. A
controlled pause immediately after that real commit is a legitimate way to land
the fault; fabricating the owner-slot relationship is not. If the
implementation only establishes that relationship after the term completes,
this schedule cannot reach K and the disposition must say so rather than
manufacture a case.

One more limit: if absent-key fencing fails before producing a durable
descriptor, a K lap measures refusal in the ordinary fencing pipeline and never
exercises descriptor classification. Descriptor consumption needs either a
legally reachable case that produces a valid descriptor, or a complete durable
fixture selected through the normal bootstrap route. A positive fencing case on
this appliance would need the owner stalled with its iSCSI session preserved,
while still satisfying real takeover eligibility — power-cutting it and waiting
past the purge interval cannot supply that.

## 3. The permanent recovery dead end is a separate, on-bar defect

Returning -ENOKEY rather than inventing a certificate is the necessary safety
behaviour and must stay. But under a bar that forbids hangs, an ordinary
in-scope fault sequence that leaves the volume in a persistent recovery dead
end is an on-bar recovery/liveness defect in its own right — equivalently, a
target/proof-model incompatibility that has to be resolved.

The logical limit matters: **"the required proof can never arrive" is not
"the proof requirement is satisfied."** Any repair has to explain why a
physically recoverable failure cannot obtain sound recovery authority, and must
not convert the impossibility of proof into permission to proceed.

Before the lap this is inspection-derived. After it, the dead-end outcome is
measured — but "forever" still needs the state-machine argument (the old term
is unchanged, no proof-producing transition is available, every ordinary mount
returns to the same refusal). A few repeated mounts do not prove permanence.

### Resealing the owner's record REFUSED is not the repair

An absent registration does not establish that the owner is dead; a live owner
may merely have lost its session and may reconnect, and the bootstrap record
may still have a live writer. Adding a REFUSED reseal to the -ENOKEY exit,
using the existing owner-mutation mechanism with no further serialisation
basis, creates an unproved concurrent-writer path. The safety-sounding name of
the destination state does not make the write safe, and a one-time CAS is
insufficient if the old owner can later issue an unconditional reseal.

A terminal cancellation protocol can be sound without claiming that fencing
happened, but it needs its own concurrency design: an independently valid
serialised or atomic conditional transition; protection against the old owner
overwriting or resurrecting the term; every owner publication path respecting
the cancellation epoch; a defined treatment of work already in flight; and no
reading of REFUSED as fencing proof or as authority to replay, replace the
owner or clear the record. A contender-owned failure report or a separate
diagnostic record avoids some of the ownership hazards — it improves
visibility, it does not retire the owner. And even a perfectly sound terminal
REFUSED still leaves the volume operator-dependent: it fixes the misleading
"apparently still progressing" presentation, not the dead end.

### What a sound repair looks like

Four families, each to be qualified against the whole safety contract:

- recover and validate an existing durable proof, where one genuinely exists
  and covers the exact owner, key, epoch and I/O outcome — a ledger status is
  not that proof;
- add an authoritative retirement/fencing mechanism whose contract covers the
  outstanding I/O, the paths and the stale-owner return behaviour;
- redesign the target ownership protocol so exclusion can be established after
  the victim registration disappears;
- change or qualify the target profile so the necessary proof operation
  survives this failure.

Empirical purge timing, local boot boundaries and a re-read showing "absent" do
not establish any of these, and introducing an otherwise prohibited node
shutdown is not a free repair. With this appliance's current behaviour and this
protocol there may be no sound automatic proof-producing operation for the
case at all; that is a design constraint to resolve, not a reason to restore
the deleted branches. `chk_mxfs --clear-bootstrap` needs an external exclusion
and recovery procedure of its own — clearing the record fences nothing and must
not discard information correct recovery still needs. Declaring
operator-certified disaster recovery to be the intended product contract would
be a scope change, not closure.

## 4. Reader closure follows dataflow, not the classifier's role name

The mint-barrier distinction in the record is correct, and it disposes of the
test the record proposed.

`mxfs_bootstrap_reseal()` classifies `args.prev_fence_kind`, a value produced
by the current attempt, so forcing it to a retired kind tests the mint/use
barrier and nothing about consuming a previously durable certificate. Writing
"kind 16" into a forged bootstrap record is meaningless as a durable-reader
test unless that kind is a real persisted field of the format, the normal path
reads it, and that persisted value is the input being classified. The
classifier context `MXFS_FENCE_RECORD_BOOTSTRAP_OWNER` existing does not
establish that such a field or such a reader does.

The descriptor route does have a durable consumer, and on the current ordering
`mxfs_v5_dlm_recovery_acquire()` is the earlier durable claim gate. So
requiring the later `P-BOOT-TAKEOVER-KIND-REFUSED` marker for an input the
claim gate already rejected is wrong; requiring `P-BOOT-TAKEOVER-UNPROVEN` is
wrong if that marker belongs to the mint barrier; and bypassing the earlier
rejection to reach either marker would not demonstrate an independent durable
entrance. The right bootstrap-route test is a complete descriptor fixture the
normal bootstrap execution actually selects, rejected at the earliest
applicable durable gate — with the correct LUN, owner/key, term and slot
identities, valid surrounding format and a supported descriptor version, with
evidence that the persisted kind reached the intended consumer, with the
rejection attributable to the kind rather than to malformed data, and with a
control showing the fixture can pass the surrounding selection machinery.

Honest disposition of the reader surfaces:

| surface | disposition |
|---|---|
| shared kind classifier | measured (0.89.17) |
| shared recovery-descriptor consumer | measured (0.89.17) |
| bootstrap invocation of those durable gates | NOT measured |
| `mxfs_bootstrap_reseal()` check | current-attempt mint barrier, not a durable reader |
| mount-time takeover check | defence in depth, dominated by the earlier claim gate |
| a separate durable bootstrap-owner-kind reader | establish by dataflow; if none exists, NOT APPLICABLE — never "tested and passed" |

## Bottom line for the ledger

- The unsafe-mint producer: fixed by inspection in 0.89.16; close its measured
  component only after a non-vacuous absent-key takeover lap plus the written
  coverage argument for the predicates the lap did not hit.
- Bootstrap-route coverage: record slotless and K separately, or a justified
  reachability disposition. Do not promote shared-function tests into measured
  bootstrap call-site coverage.
- The reader allegation: narrow it to actual persisted-input consumers, and
  drop the obligation to test a reader that does not exist.
- The persistent recovery dead end: file separately as an on-bar blocker for
  this target and failure model. Closing the integrity defect must not imply
  that bootstrap recovery, or the release bar, has passed.
