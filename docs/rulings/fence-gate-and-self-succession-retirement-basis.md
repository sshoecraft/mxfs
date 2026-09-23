# The gate and self succession: what a retirement basis may and may not rest on

Design-consult ruling (Astra, session 81) on
`D-GATE-AND-SELF-SUCCESSION-KINDS-CERTIFY-FROM-ADMISSION-WITH-NO-RETIREMENT-BASIS`
— the two remaining replay-authorising fence kinds that consult no retirement
basis.  It continues `fence-ambiguous-drain-and-proof-resume.md` (a certificate
needs ADMISSION and RETIREMENT, and they are separate facts) and the 0.89.13
package that gave boot succession a fail-closed basis.

Protocol reasoning, not an attestation about the QNAP's unreported behaviour.

## The ruling in one line

> The correct split is "the victim's work was demonstrably within the completed
> retirement operation's scope" versus "it was not."  It is **not** "the key was
> present in an earlier snapshot" versus "absent."

With the observations available: **contract-or-refusal for kind 20, and refusal
by default for kind 19.**

---

## Kind 20 — the sole-survivor exclusive-write gate

### The pre-read is not a witness, and the race is the reason

The proposal was: read the registration list immediately before the gate's
`sark=0` PREEMPT AND ABORT; if the victim's key was present, the operation
aborted its task set, so the basis is a real target operation.  That is unsound.

| time | event |
|---|---|
| T0 | target accepts victim write W |
| T1 | READ KEYS reports the victim's key PRESENT |
| T2 | target removes the victim's registration on session loss — nothing established proves W retired here |
| T3 | the gate's PREEMPT AND ABORT executes; the victim's registration is no longer among those it removes |
| T4 | the gate completes successfully and excludes subsequent non-holder writes |
| T5 | without a retirement guarantee, an unordered effect of W remains unexcluded by the proof |

The pre-read and the successful operation look **exactly** as they would in the
good execution where the operation really did abort the victim's task set.
Recording the earlier observation at completion does not make that observation
contemporaneous with the operation's scope selection.

### What a sound TARGET_OP would need

One of: an operation whose defined successful completion establishes the
retirement postcondition *independently of whether the registration still
exists*; target-provided evidence that the completed operation actually included
every relevant victim nexus and task set; or a real serialization guarantee
keeping those registrations in scope until the operation acts — which must also
exclude autonomous target-side removal on session expiry, not merely another
MXFS thread issuing PR commands.

The appliance interface supplies none of these for a zero-SARK gate.  And
switching to `sark=victim` does not automatically fix the evidentiary problem:
**"the command named the key" and "the command demonstrably retired that key's
work" are different claims.**

### The shape to implement

```
gate completed:
    establish admission witness

retirement:
    use an independently captured, correctly scoped retirement witness
    else use a matching contract whose actual trigger is established
    else refuse the certificate
```

**Measured in this tree, and it removes the branch entirely:** the gate is
attempted only from the KEY_ABSENT_UNPROVEN classification, and its own log line
says so on every occurrence — `P238-FENCE-GATE-TRY … victim key already absent`,
every one of 55+ occurrences across 20 laps on 2026-09-20.  So the gate's only
reachable case is the one where the pre-read would have found the key absent
anyway, and contract-or-refusal is the whole implementation.

### The trigger still has to be established

The shipped clause is a **lost-nexus** clause: every command accepted from the
lost nexus completed or aborted, effects ordered before subsequent I/O, before
that nexus's registration disappears.  It "is applicable only when the
disappearance is within its covered loss transition.  It is not automatically
applicable to arbitrary key absence caused by key replacement, explicit
unregistration, or another transition."  So the gate must record the observed
trigger, not merely that a key is missing.

### A separate prerequisite, to be checked and recorded on its own

Zero SARK is **not** a universal "remove every other registration" selector in
every PR state — the all-other-registrations behaviour depends on the existing
reservation state, specifically the all-registrants case, and asking for a
resulting type-1 reservation does not establish it.  Check that the gate starts
in the legal state for the operation, and record it separately from retirement.

---

## The gate as an admission barrier

The measurement — while the single-holder Write Exclusive gate is valid, ordinary
writes from the returning non-holder incarnation are rejected by the target — is
a genuine and strong admission fact.  It closes a successor-admission concern.
It changes nothing about commands already accepted from the predecessor:

```
predecessor:  W accepted ---------------- possible later effect
survivor:                gate completes ---- replay
successor:               writes rejected throughout gate lifetime
```

Successor rejection does not cut the predecessor's line.

Two corrections to how that measurement may be used:

- **Publishing a key into MXFS's on-LUN metadata is a WRITE; issuing PR OUT
  REGISTER is not the same thing.**  The observed `P-PRKEY-PUBLISHED … rc=-52`
  refusal must not be generalised into "the returning initiator cannot register
  or manipulate PR state."
- The admission proof needs the gate's **continued validity**, not its
  installation: relevant paths and nexuses, holder identity, and protection
  against premature clearing or preemption.  Its release condition is completion
  of the recovery dependency — never certificate sealing or publication.

---

## Kind 19 — self succession

### REGISTER AND IGNORE forces no session outcome at all

The kind claims exclusion by "the boot boundary + nexus reinstatement (the old
task set died with the old session)".  The transitions are distinguishable, and
a fourth case defeats the claim outright:

| observed transition | what it establishes |
|---|---|
| Login with **TSIH=0**, same InitiatorName/ISID, same target session scope | requests a new session that must reinstate a matching existing one; full session reinstatement terminates the old session's active tasks |
| login/recovery within an existing session, using its nonzero TSIH | NOT full reinstatement; connection recovery can preserve tasks and support task reassignment |
| new session with a different ISID or target session scope | does not replace the old session merely by existing |
| **no session transition at all — REGISTER AND IGNORE changes the key on the existing nexus** | no session-retirement event whatsoever; existing tasks can remain active |

A same-host module restart can leave the iSCSI session completely unchanged.
Current session state cannot reconstruct which happened: the old identity —
InitiatorName, ISID, TargetName, TPGT, old TSIH, connection IDs, negotiated
ErrorRecoveryLevel — has to be captured *before* it is lost, along with the
Login exchange and its transition to Full Feature Phase.  An IP address, a Linux
session number, a TCP connection or a device pathname is not a sufficient
identity.

Even a deliberately enforced full reinstatement has limits: a successful
same-identity zero-TSIH login does **not** report "I found old session X and
aborted these tasks" — if the old session was already gone, the same login
succeeds as plain session creation.  A proof must cover that already-gone case
through applicable teardown guarantees or a contract, and must not invent an
observed abort.

### The shipped clause does not cover it

Same-nexus key replacement has neither of the clause's events: the nexus stays
live, its registration stays present under a different key, and previously
accepted tasks can stay active.  **"Old key absent" is not equivalent to "old
nexus lost and its registration removed."**  A differently worded clause is
logically possible — asserting that successful completion of the specified
REGISTER AND IGNORE on nexus N is itself a retirement barrier for everything
previously accepted on N, including same-session key replacement without nexus
loss — but that asserts *more* than ordinary REGISTER AND IGNORE semantics, is
not derived from the loss clause, and has no evidence behind it here.

### A second defect the record did not name

Ordinary WRITE commands do not carry the PR registration key as an incarnation
credential.  If the old and new MXFS generations share the same live I_T nexus,
changing that nexus's key may leave an **old local writer able to submit through
the newly registered nexus**.  Old-key absence does not exclude an old local
issuer using the successor's transport.  Kind 19 therefore needs an explicit
old-generation admission barrier; retirement qualification cannot substitute for
it.

### Ruling

**Refuse kind 19 by default.**  Enable it only through an explicitly implemented
route supplying old-generation admission, a scoped retirement witness or an
explicitly applicable contract, and a captured proof tied to the actual
transition.  Refusal is preferable to pretending the loss contract fits; a
correctly worded supported contract is not inherently inferior to refusal, but
an unsubstantiated renamed assumption is.

---

## Shortcuts that would recreate these defects

| shortcut | why it fails |
|---|---|
| "the key was present immediately before the P&A" | removal can occur between the snapshot and scope selection |
| "present before, absent after, and it returned GOOD" | does not prove which event removed it or retired its work |
| "the PR generation changed as expected" | a snapshot counter is not a compare-and-act guard or a retirement receipt |
| "the successor gets RESERVATION CONFLICT" | admission exclusion, not retirement |
| "REGISTER AND IGNORE completed" | registration mutation is not an implicit task-set abort or drain |
| "same host, new key, therefore boot boundary" | neither a key change nor a module restart necessarily changes the session or stops old local submissions |
| "the TCP connection died / the queue emptied / the timeout expired" | local error completion is not remote cancellation |
| "wait longer than the measured 34 s" | purge timing bounds nothing about previously accepted effects |
| "SYNCHRONIZE CACHE or FUA will fix it" | durability operations do not stop an old still-live task from writing later |
| "recovery is sealed" | sealing neither retires old work nor releases an admission dependency |

## The basis enum must not become another label

A nonzero basis is necessary, not sufficient.  `TARGET_OP` must not mean "some
target command completed", and `QUALIFIED_CONTRACT` must not mean "this LUN has
some qualification".  Evidence should carry: the basis, the exact claim or
operation, the victim incarnation, the covered nexus/session set, the LU and
firmware identity, the **observed trigger**, and the completion boundary or
contract reference — alongside an admission witness naming its mechanism, scope,
authority epoch and release condition.

Keep **separate claim identifiers** for lost-nexus registration removal,
same-nexus registration replacement, and completed full session reinstatement.
Sharing fingerprint-matching code is fine; sharing an undifferentiated
"qualified" boolean is not.  And a predicate taking only `kind` cannot decide
whether these contextual obligations were met: it can identify a potentially
proof-bearing kind, but acceptance must validate the certificate's evidence and
the permitted kind/claim/transition combination.

## Arms that test the evidence boundary, not just successful fencing

| arm | required outcome |
|---|---|
| kind 20, no contract, key initially present, pause between the read and the gate while the registration disappears | no TARGET_OP certificate from the stale pre-read |
| kind 20, no contract, key already absent | zero certificates; recovery refused |
| kind 20, exact matching loss qualification and covered loss transition | certificate explicitly names the qualified-contract basis |
| kind 20, wrong firmware | zero certificates; firmware-specific refusal |
| kind 19, same live session, key replacement, loss-only contract | refusal: wrong transition for that clause |
| kind 19, different-ISID independent session | no reinstatement-derived retirement claim |
| kind 19, deliberately enforced full reinstatement | capture the old identity, the Login exchange, its completion and the complete session scope; grade only the witness actually implemented |
| returning victim writes while the kind-20 gate stands | target rejection throughout the recovery dependency, including after certificate sealing |

The first needs no target tracing: pause on the initiator side after the
pre-read, let the real disappearance happen, then run the gate.  It demonstrates
why the observation cannot justify the branch without manufacturing corruption.

Repeated runs with no late overwrite can support deployment qualification; they
cannot turn a missing retirement acknowledgement into an observed per-execution
witness.  Where neither a correctly scoped completion witness nor an applicable
supported contract exists, the honest support boundary is **"no replay-authorising
certificate"**, not "probably drained".
