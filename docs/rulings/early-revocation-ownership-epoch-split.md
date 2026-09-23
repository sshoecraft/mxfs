# Early revocation as an ownership epoch, and what the live-loser evidence does not yet cover

Design-consult ruling (Astra, session 86, 0.89.19), continuing
`retirement-witness-routes-lu-reset-early-preempt-or-refuse.md`. It answers
whether route 2 — fence before the association is lost — is implementable now
that the live-loser behaviour has been measured, and what the all-node mount
refusal measured this session is honestly called.

## The ruling

> Route 2 is implementable as an **opportunistic, verified revocation of a
> storage incarnation** — not as a guarantee that fencing will beat
> registration purge. The sound outcome set is: a verified scoped PREEMPT AND
> ABORT retains the retirement witness and proceeds through the ordinary
> recovery gates; otherwise, refuse.

The missing LU-reset leg makes the mechanism **narrower, not unsound**. But
moving the PREEMPT AND ABORT earlier, without the ownership/membership split
and without closing the delayed-containment cases below, is not a sound
implementation. Nothing here restores the withdrawn deployment clause.

## 1. What the live-loser lap established, and the ordering it did not

The alive-but-silent victim lap (0.89.19,
`tests/evidence/20260920T134039Z_fcut7_s86b_cut7`) establishes that a live,
actively issuing node can meet reservation conflicts, confirm through PR IN
that its own registration is gone, withdraw its mount without taking the node
down, and **stay** withdrawn when the target later becomes permissive. That
last part is the strongest of the four — it is more than "PR kept rejecting
writes".

What it demonstrates is **preservation of a containment latch that was already
established**. It does not demonstrate that the latch gets established in every
ordering. The one that matters:

1. B is alive but its execution or I/O path is stalled.
2. A successfully preempts and aborts B.
3. B has not yet processed a reservation conflict, an ownership-loss
   notification, or a confirming PR read.
4. A crashes.
5. The appliance purges A's last registration, and the reservation with it.
6. B resumes, still believing its old storage incarnation owns the mount.

**If the reservation-free LUN then accepts B's writes, B writes stale state
without ever re-registering.** The lap's "zero successes after the last
reservation disappeared" does not cover this: B had already detected its
eviction and withdrawn before that point.

This is not an argument for waiting longer, and polling PR state more often is
not a fix — a PR read is not an atomic ownership check bound to the writes that
follow it. Eventual detection of ownership loss is insufficient if stale I/O
can become admissible before detection.

### The invariants a release argument needs

- An old storage incarnation cannot resume I/O after revocation.
- Queued, retried, delayed and asynchronously generated I/O obey that rule —
  not just new system calls.
- Losing access does not require successful LUN access to contain the mount.
- Neither session recovery nor membership recovery silently restores ownership.
- Delayed DLM messages and dirty-state transfers from the revoked incarnation
  cannot reintroduce its state through another node.

### The five measurements, and what makes each vacuous

**A. Slow or suspended execution.** Revoke B while delaying it at different
points — before an ownership check, after the check but before submission,
during journal commit, during writeback, and before handling a loss
notification — and resume it both while A's reservation stands and *after the
target has removed the last reservation*. The after-check/before-submit case is
the point: a successful earlier ownership check must not become a reusable
permission token. *Vacuous if* B never resumes, the workload stops submitting,
only the heartbeat thread is paused, or every run lets B latch withdrawal
before target-side protection disappears.

**B. DLM partition with storage intact.** Partition the DLM connection without
disturbing either iSCSI session: asymmetric partitions, simultaneous suspicion,
outstanding lock requests, dirty-state transfers, reconnection with delayed
messages. A losing node must not regain authority because TCP reconnected.
*Vacuous if* the fault also breaks iSCSI, reboots the loser, stops its
workload, or avoids simultaneous suspicion; a run with no relevant DLM traffic
validates nothing about stale grants.

**C. Long I/O stalls and outstanding work.** Delay submissions and completions,
exercise timeout and error handling, leave asynchronous writeback outstanding
across the revocation, and stall the PREEMPT AND ABORT itself. Required: a
verified completion gives only the scope the accepted basis establishes; an
incomplete, ambiguous or timed-out attempt produces no certificate; neither
containment nor fencing holds an essential lock indefinitely; old queued work
cannot resume under a later ownership incarnation. *Vacuous if* the stall
happens before any relevant work is outstanding, or the injection just returns
immediate errors through a convenient path. Note that without target
instrumentation, host-side "outstanding" is not "accepted by the target" — this
test must not be used to recreate an appliance-retirement guarantee.

**D. Containment when the LUN is unusable.** Make the confirming PR read fail or
stall; withdraw while locks are held, under writeback and reclaim pressure, and
with the diagnostic destination unavailable. The local safety gate must not
depend on first completing a journal update, a log write or a successful PR read
on the fenced LUN. Confirmation may refine the diagnosis; uncertainty must not
reopen writes. *Vacuous if* PR IN always succeeds promptly, the locks are
conveniently free, or the only failure tested is the data write that leads
straight into the existing happy-path withdrawal.

**E. Re-entry and the full crash pipeline.** iSCSI reconnect, DLM reconnect,
mount retry, local recovery workers, reboot and every automatic registration
path; then the prover crash cuts again with early revocation on, crashing
before submission, after submission but before a known completion, after
completion but before durable evidence, and during recovery before its
completion marker. *Vacuous if* the harness recreates ownership
unconditionally, supplies a certificate, restores a clean image, or avoids the
interval where the completion witness is not yet durable.

### What to verify besides return codes

The fsync and metadata-prefix results are good containment evidence, but a
failed fsync does not prove nothing reached media; a successful fsync returning
after the PREEMPT AND ABORT is not automatically a violation if its durability
was established before revocation; and a contiguous acknowledgement prefix does
not by itself establish that the acknowledged namespace survives recovery.
Correlate operations with ownership epochs, issue and completion paths,
withdrawal, and recovery results.

## 2. The minimal sound split

Two independent state machines:

- **machine membership** — alive / suspect / dead;
- **storage incarnation** — owned / revocation pending / revoked / recovering /
  eligible for fresh admission.

**"Alive but revoked" has to be a real supported state**, not an accidental
interval between two existing ones.

1. **Suspicion initiates an attempt, not a certificate.** An authorised node may
   attempt the scoped PREEMPT AND ABORT. It may not claim retirement, reclaim
   the suspect's locks or journal, read a timeout as success, or treat an
   earlier PR read as having captured the registration's scope. There must be a
   rule for simultaneous suspicion that does not let each loser re-register and
   keep fencing the other.
2. **Apply the existing accepted-basis verifier**: the intended
   registration/nexus was genuinely in scope, the scoped operation completed,
   the required post-state was verified, and the issuer still holds the
   authority to act on the result. A previously observed key followed by an
   absent key is not enough, and a generic "command succeeded" is not enough if
   the wrapper cannot distinguish the scoped operation from one without that
   scope. **The appliance's unchanged PR generation is especially unsuitable as
   evidence that no relevant state changed.**
3. **Record the revocation**, bound to the LUN, the victim storage incarnation
   and registration, the operation, the verified result and the protocol epoch;
   durable if a later recovery or successor must rely on it. Successful early
   revocation is **not reversible because the suspect later proves alive**.
   There remains a crash window between target completion and durable
   recording: an issuer that dies there leaves a successor that must refuse.
   An intent record is not a completion witness.
4. **Recovery stays behind the ordinary certificate.** Early retirement evidence
   is not permission to replay. Do not release old locks and let another owner
   modify their protected state before the required recovery; reject stale
   grants, callbacks and dirty-state transfers from the revoked incarnation; and
   do not let an alive-but-revoked member stay an ordinary storage participant
   merely because its membership timer has not expired.

**What the revoker owes a suspect that turns out to be alive:** its old mounted
storage incarnation stays withdrawn; its journal and locks are resolved under
the normal certified recovery rules; its cached ownership and mutable state are
discarded or safely reconciled; and it may then receive fresh coordinated
admission under a new incarnation with a properly bound registration. The
machine stays alive throughout. The trap in keeping the existing death
schedule: **if the suspect's heartbeat resumes and the death decision is
cancelled, the ownership-revocation obligation does not disappear** — there has
to be a storage-owner readmission transition that does not require falsely
declaring the machine dead. If the DLM cannot represent that distinction,
moving the PREEMPT AND ABORT earlier is not the minimal complete
implementation.

**Re-registration** is already a hazard for any PR-based fence; early revocation
makes the live-node version routine. Audit every registration path — reconnect,
boot, mount retry, error recovery, administrative helpers. Neither "my key is
absent, therefore register it again" nor "the peer is alive again, therefore
restore its old ownership" is acceptable. And re-registration is not the only
reopening hazard: the disappearance of the last reservation may itself make the
target permissive.

## 3. There is no safety-derived interval

The measurements supply no safe deadline: neither 30 s nor any fraction of it is
a proven minimum retention, and the time from power cut to suspicion is not
bounded by choosing a short timer — scheduling delay, transport detection,
command queuing and error handling all intervene.

> Trigger early for availability; authorise recovery only from verified facts.

Choose the interval from false-revocation cost, workload latency, scheduling
behaviour and measured success rate, and **keep the interval out of the safety
argument**. A reasonable implementation combines a raw DLM transport-loss
notification considered before the existing membership grace, a separate short
heartbeat-suspicion threshold, relevant PR-state notifications, and the existing
later membership classification. None of them guarantees the registration is
still there.

**Event-driven does not mean guaranteed early.** A DLM disconnect is suspicion,
not storage retirement. A PR-state notification may only be delivered when a
command meets the condition, may go to the affected node rather than the
prospective revoker, may report a change that has already destroyed the
opportunity, and is not guaranteed at all for a silent internal purge.

**The discarded UNIT ATTENTIONs**: a prerequisite for an event-driven
PR-notification trigger — that trigger cannot be claimed while the wrappers
discard the sense. Not a prerequisite for route 2's abstract validity. For the
switch-on decision they are a **gating audit item**: establish whether a
relevant UA can be consumed and retried without invalidating ownership, which
would let a delayed loser proceed once the reservation has gone. Preserving UAs
is not by itself proof of admission exclusion.

## 4. Without the reset leg: narrower, and not a repair for the dead end

The sound structure is: scoped operation established → use its witness inside
the ordinary recovery protocol; scope absent, completion uncertain,
verification failed or evidence lost → refuse. An unsuccessful attempt can
still leave a permanent in-product recovery dead end, and early revocation adds
availability costs of its own — a false suspicion withdraws a healthy mount, and
a revoker crash can leave neither participant able to continue.

**Why it does not generally repair the all-node refusal.** There are two
retirement obligations: the original victim's, and **the prover's, which issued
replay writes of its own**. A durable certificate for the victim does not retire
the dead prover. If the prover's registration has already gone, the same
missing-basis problem recurs; if both nodes are down, or no authorised node runs
the fast path before the purge, there is no actor to win the race, and a later
boot cannot retroactively perform the missing scoped abort. Route 2 improves the
*fraction* of crash cuts that recover. It cannot make the matrix recoverable
under arbitrary outage timing. The old 12/12 result is not qualification
evidence for the current retirement protocol.

### What the refusal leg must preserve

A recoverable intermediate state, not merely a bounded error: source journals,
ownership identities, certificate records, execution-lease provenance and
replay-progress records. Do not retire, zero, truncate or reuse the journal or
slot on an unproved path; do not mark a partially applied replay complete; do
not clear the dead prover's lease because its timer expired; do not let a new
writable mount build on metadata whose previous writer is unretired; and keep
the distinction between operation intent, observed completion and durable
completion evidence. Retries must be bounded and end in an explicit terminal
diagnostic — time spent retrying supplies no new retirement fact. A future
witnessed mechanism must be able to retire the outstanding issuer, supersede its
execution lease and resume or restart replay, which additionally requires
proving replay's crash-restart behaviour: preserving the log is necessary and
not sufficient if the partially applied state cannot be replayed correctly.
Until retirement is established, treat possible late effects as unresolved — do
not assume the quarantined metadata has stopped changing because the mount was
refused.

## 5. How the all-node mount refusal is honestly classified

Against a bar that reads *nothing may corrupt or lose data, and nothing may
crash, hang or shut down a node*: a bounded, explicit mount refusal is not a
node crash, a node hang, a node shutdown, or demonstrated data loss. Indefinite
service unavailability is not an operation hanging indefinitely. So — assuming
the intermediate state really does preserve everything recovery needs — the
outcome is inside that narrow negative safety property and outside availability
and recoverability guarantees the wording does not contain.

That is the literal classification and not a reason to call the release
successful. Three qualifications:

1. **Failing closed does not prove no data loss.** It still has to be
   established that acknowledged data and recovery sources survive, and that
   interrupted replay can eventually reconstruct a valid state.
2. **"No automatic recovery" is not "data destroyed"** — but with no supported
   way to complete recovery, the data must be described as *inaccessible*, not
   as something an ordinary retry or reboot will get back.
3. **If ordinary hard-failure recovery is a release requirement, this fails
   it**, and that cannot be waived by calling the failure availability.
   Conversely, calling a bounded refusal a node hang would misclassify what was
   observed.

The truthful release statement is substantially:

> MXFS fails closed when it cannot establish retirement. On this QNAP
> configuration, an ordinary hard failure — including failure of a node
> performing recovery — can leave the volume unmountable on every node. After
> registration purge, the current implementation has no supported in-product
> mechanism to establish the missing retirement basis. Early revocation may
> avoid this condition when a verified scoped PREEMPT AND ABORT succeeds, but
> does not guarantee recovery. Crash-matrix results obtained with the withdrawn
> retirement basis do not qualify this build.

It must not be abbreviated to "safe failover", "automatic recovery", or an
unqualified "100% integrity and stability passed".
