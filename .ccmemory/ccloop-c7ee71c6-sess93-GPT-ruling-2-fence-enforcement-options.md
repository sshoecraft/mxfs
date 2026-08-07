---
name: ccloop-c7ee71c6-sess93-GPT-ruling-2-fence-enforcement-options
description: sess93 RULE-5 ruling #2: PREEMPT AND ABORT is NOT a durable host fence. Periodic-P&A and enumerate-unknown-keys are UNSOUND; temporary WRITE EXCLUSIV…
metadata:
  type: reference
tags: [sess93, GPT-ruling, RULE-5, fencing, scsi-pr, D-FENCED-VICTIM-MAY-REREGISTER, binding, write-exclusive]
---

# sess93 ruling #2 — how (and whether) MXFS can actually fence a live victim

Asked with the sess93 measurement in hand (a PREEMPT-AND-ABORTed node
re-registered and wrote seconds later). BINDING.

## Headline

> Your measurement **invalidates PREEMPT AND ABORT as a durable host fence.**
> It is a point-in-time removal of registrations and tasks, not revocation of
> the initiator's ability to register again.
>
> For an ordinary shared-write SCSI LUN there is **no fully sound, persistent,
> in-band fence against a still-running initiator that may register under a
> fresh key.** SCSI PR does not bind keys to cluster identity or authorize who
> may register. Keys are not secrets, and PR provides no deny-list.

And the naming correction, which is directly actionable:

> Your existing certificate **should no longer be called a fence certificate**
> unless it represents either a continuing exclusive-write reservation or
> continuing target/fabric exclusion. PREEMPT AND ABORT alone is evidence of a
> **completed eviction event**, not evidence that the host remains fenced.

## The four options, ranked

### 1. (d) target/fabric revocation — SOUND, but outside a kernel FS module
Revoke every target path for the victim's **stable** initiator identity (IQN,
WWPN, host object, ACL). Must cover every path and session, abort/drain
outstanding commands, reject both ordinary I/O **and PR OUT**, remain in force
through recovery until explicit readmission, survive recovery-owner failure,
and identify the host independently of MXFS's random per-mount key. Needs a
fencing agent / array API / cluster fencing daemon / administrator. The
certificate must attest to a **continuing** exclusion, not that a revocation
command once succeeded. This is the only listed option that stays sound if the
victim may deliberately re-register, pick another key, or issue PR control
commands.

### 2. (a) temporary WRITE EXCLUSIVE gate — best purely in-band, CONDITIONALLY sound
Convert WE-RO → ordinary single-holder WRITE EXCLUSIVE for the replay window.
Then the TARGET rejects writes from every non-holder, **including a victim that
successfully registers under a fresh key**. Materially stronger than key
removal. Six requirements:
1. **Quiesce all cooperating nodes FIRST** — stop new writes, drain outstanding
   I/O on every healthy node, and do not let RESERVATION CONFLICT escape into
   XFS as ordinary I/O failure.
2. **No unreserved gap** — never RELEASE-then-RESERVE; use an atomic PR
   transition (normally the appropriate PREEMPT), and verify the exact SPC
   behaviour on **both LIO and SCST** and on representative arrays.
3. **Still issue PREEMPT AND ABORT** — WE stops *later* non-holder writes;
   commands already outstanding at the victim's nexus still need aborting. The
   durable gate certificate is issued only after that boundary.
4. Hold WE continuously through replay and publication.
5. **Takeover must atomically acquire/transfer the single-writer reservation** —
   no unreserved or WE-RO interval during takeover.
6. Restore WE-RO only after publication, when the cohort can safely resume.

Effect on the 30 innocent nodes: their writes get RESERVATION CONFLICT — this
does not "pause" them, it can shut their filesystems down. **"Convert and let
their I/O bounce" is unsound**; they must participate in an MXFS-level
freeze/drain protocol first, and a non-cooperating node is then treated as a
fenced node. Their registrations can stay (less churn); under ordinary WE a
non-holder registrant still cannot write.

Two limits: (i) protection lasts only while WE is held — on restore to WE-RO any
registrant can write again, so it is not a permanent host fence; (ii) **SCSI PR
is not Byzantine-safe** — an initiator allowed to issue PR OUT can register,
read the reservation key, and try to preempt the WE holder. Sound only under the
narrower model that failed/stale nodes may resume data I/O and registration but
do not steal the reservation.

### 3. (b) re-verify before each destructive step — DETECT-ONLY, not enforcement
The race is explicit: `READ KEYS says absent → victim registers → victim writes
→ recoverer performs destructive step`. Cannot satisfy requirement B as safety.
Still worth shipping as invariant checking, fault detection, telemetry, and a
guard against accidental reservation loss / target defects. **On detection: do
NOT continue replay** — enter a failed/blocked state, prevent normal cluster
I/O, require offline repair or a sound fence. "Aborting half-replay may leave an
indeterminate image, but continuing after exclusion has been disproved is not
safer." Re-verification does not make partial in-place replay transactional.

### 4. (c) periodic PREEMPT AND ABORT — **UNSOUND**
Repeating P&A against the ORIGINAL key does not fence a victim that registers as
another key. Even at 500 ms it gives no integrity bound: **one accepted sector
write invalidates the recovery. "Bounded exposure time" is not "bounded
damage."** Plus PR generation churn, target serialization, repeated task aborts,
multipath inconsistency, collateral removal of legitimate registrations, and bad
takeover behaviour. May be a cleanup measure AFTER real exclusion exists; must
never be credited as fencing.

### Enumerate-and-preempt-unknown-keys — **ALSO UNSOUND**
`READ KEYS → classify → PREEMPT unknown` is inherently non-atomic; a node can
register and write after the read, during classification, or under another key.
Misclassifies a legitimate join; a rolling-upgrade cluster has no complete
known-good set; multipath shows one node through several nexuses; a truncated
READ KEYS hides registrations; a victim can cycle keys faster than the loop; and
preempting a key after it has written undoes nothing. Fundamentally it makes the
recoverer an **unauthenticated target membership authority** while the target
cannot tell a legitimate key from an illegitimate one. If joins must be
supported during recovery the clean rule is: **do not permit joins while the
exclusive recovery gate is held** — queue or reject them.

## Q3 — the honest system formulations

In-place foreign XFS log replay has a **quiet write domain as a hard
precondition**. It cannot be made correct by documenting or detecting concurrent
writes. Viable formulations:

- **A. Require a continuing external fence.** Without a sound fencing backend:
  do not begin destructive foreign replay, surface
  `RECOVERY_BLOCKED_NO_ENFORCED_FENCE`, require an admin/agent to establish
  exclusion, and only then mint the authorization. Fail-closed, not acceptance
  of corruption. "If the release bar does not permit a blocked manual-recovery
  mode, such configurations cannot support automatic foreign recovery."
- **B. Temporary WE as the supported in-band gate** (conditions above). The
  certificate then becomes *"Recovery epoch E currently owns the
  target-enforced exclusive write gate"* — **not** *"victim key K was absent at
  time T."*
- **C. Architectural redesign** — COW recovery into an isolated clone plus an
  atomic namespace/LUN switch; immutable epoch-separated metadata; target-
  enforced epoch/write capabilities; per-node isolated logging with a
  publication mechanism stale writers cannot overwrite; or a target-side
  compare-and-publish primitive. NOT a local XFS replay change. On-disk epoch
  tags can detect stale writes after the fact but cannot stop a stale initiator
  overwriting the sector holding the new data or tag. **"There is no credible
  small reformulation in which current in-place XFS replay remains correct
  while an arbitrary partitioned victim may concurrently write the same LUN."**

## Q4 — the verification that would prove a WE gate

Acceptance test must keep the victim ALIVE and hostile. Prove from target/block
traces the exact ordering: cohort stops writes → cohort drains → reservation
atomically becomes single-holder WE → victim's outstanding tasks aborted → gate
certificate durable → replay → publication durable → WE retained to the
publication boundary → restore WE-RO → cohort resumes. **No unreserved or WE-RO
gap between steps 3 and 8, including during owner takeover.**

Live-victim workload, continuously and on BOTH multipath paths: write with the
old key; REGISTER AND IGNORE a fresh key then write; unregister/re-register
another key then write; fail paths and retry on the survivor; submit writes
before the transition so some are in flight; issue several write-like commands
covered by the PR access table, not only plain WRITE. Expected while WE is held:
registration may succeed, but every non-holder write gets RESERVATION CONFLICT,
no victim write changes the scratch or metadata LBA, and every command completed
after the certificate is attributable to the WE holder.

Also verify: the recoverer can write through every intended path; the 30
innocent nodes see no filesystem-visible I/O failures (because they froze
first); owner death mid-replay transfers the gate without a writable gap; the
old owner cannot write after takeover; publication never happens after gate
loss. Plus a NEGATIVE test where the victim deliberately PREEMPTs the WE holder
— if it can steal the reservation, that demonstrates the threat-model boundary.

## Plain disposition as given

- (a) conditionally sound for the replay window as a coordinated global
  single-writer gate; not a permanent host fence; not safe against arbitrary PR
  preemption.
- (b) detect-only; useful, not safety enforcement.
- (c) unsound. Enumerate-and-preempt unknown keys: unsound.
- (d) sound general solution, necessarily outside a portable kernel FS module.
- Current in-place replay with an unfenced concurrent writer **cannot be made
  correct by a check, a timeout, or a certificate wording change.**
