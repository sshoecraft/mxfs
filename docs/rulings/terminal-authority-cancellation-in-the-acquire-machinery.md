# Terminal authority cancellation, and why it is not another peer-failure case

Design-consult ruling (Astra, session 88). It continues §5a of
`local-authority-lease-and-the-limits-of-a-software-gate.md` — "indefinite
blocking is not an acceptable withdrawal mechanism" — now that the lease itself
is implemented, mount-owned and measured.

## What was brought to it

Established by reading the code, not yet by instrument:

- The acquire is not one long sleep. `pending_wait()` is a condvar timed wait of
  about a second per attempt, and `mxfs_dlm_lock()` drives
  `mxfs_dlm_lock_retries(..., 60)` around it, so a blocked waiter returns to a
  loop roughly once a second.
- `dlm_lock_impl()` tests `ctx->shutting_down` at entry, but
  `ctx->dlm->shutting_down = true` is set **only** in
  `mxfs_v5_dlm_shutdown_defer_release()`, which runs at unmount. The withdrawal
  path does not set it: it poisons the v5 context, stamps the slot WITHDRAWN,
  stops discovery, and deliberately keeps lease renewals running so peers do not
  remaster this node before its slice is replayed. Its own comment says
  "conflicting acquires ride their 60 s budgets through the few-second window."
- There is already an acquire-path fail-fast, `recovery_blocked_cb`, but it is
  keyed on a *peer's* slot being a dead node whose recovery is blocked.
- There is a registered-fallibility distinction, `acq_fallible_cb`, and it was
  itself the fix for a measured shutdown storm: a non-fallible caller — an AG
  acquire inside a dirty transaction — is deliberately never failed, because
  handing it `-EREMCHG` would cancel dirty and shut the filesystem down.

## The ruling

> Based on the paths you describe, I would narrow the original finding: this
> acquire loop is **withdrawal-insensitive, not demonstrably an indefinite
> sleep.** Whether the complete operation is bounded still depends on
> non-fallible handling, outer retries, and cleanup waits. A one-second timed
> wait and a retry count do not establish that end-to-end bound.
>
> That changes the cancellation mechanism required; it does not make riding the
> remaining budget an adequate response to terminal authority loss.

### 1. CLOSED overrides fallibility, but the unwind must be a shutdown unwind

The two cases mean different things. With authority OPEN and a peer's recovery
blocked, failing a non-fallible acquire might destroy an otherwise viable
transaction and mount — which is what the fallibility distinction protects. With
authority CLOSED, this incarnation can no longer complete the transaction
normally, and keeping the acquire alive cannot restore that ability.

> An otherwise healthy node whose authority expired belongs to the second case.
> **Health is not authority.** There must not be a "CLOSED, but healthy enough
> to continue" exception or an implicit reopening following a late renewal.

But this does not license a bare `return -EIO` in a must-succeed path. It needs
a terminal **shutdown** unwind:

- transaction cancellation must not commit deferred work, force a log, or start
  writeback under the closed authority;
- committed journal state and replay obligations stay intact — "cancel dirty"
  does not mean "discard what recovery needs";
- callers release local locks, pins, references and reservations without waiting
  for the missing grant;
- a caller that currently asserts on acquisition failure needs an explicit
  shutdown case.

**An ordering hazard that is specific to this design.** Authority closure
precedes the withdrawal pump's filesystem shutdown, so a waiter can observe
CLOSED and return an error *before* the shutdown state is published. Either
publish the logical shutdown state before those failures become visible, or make
the unwind recognise CLOSED directly. Do **not** wait for the whole shutdown
procedure before cancelling acquires — that procedure may itself be waiting for
them.

Keep this separate from `recovery_blocked_cb`: local authority loss is not
another dead-master recovery condition. And note that a non-fallible
classification is not proof that the operation has a dirty transaction — the
pre-opened-fd read is a useful regression case, but an acquire with real dirty
transaction state must also be exercised.

### 2. The error: terminal internally, `EIO` externally

`-ESHUTDOWN` as the DLM's internal result, consistent with its existing terminal
result; normalised to `-EIO` at the filesystem boundary, consistent with the
write gate. Using `-EIO` throughout is also defensible.

> The important property is not the errno's spelling: **every retry layer must
> treat closed authority as terminal.**

No fallible/non-fallible distinction in whether cancellation is terminal; no
conversion into `-EREMCHG` or another "retry after recovery"; no generic "any
acquisition error means retry" wrapper; no teardown path that starts another
acquire to compensate. The retry decision consults the terminal authority state,
not the errno — otherwise a simultaneous transport timeout supplies a nominally
retryable error while authority has already closed.

And: do not blindly set the existing `shutting_down` flag without auditing its
readers. If it disables control-plane activity needed to preserve recovery
exclusion it conflates two states that must stay separate — *productive
acquisitions are closed; recovery and control-plane obligations remain*.

### 3. Polling can bound this wait; a top-of-loop check is not the whole fix

An explicit wake is not required merely to get a roughly one-second cancellation
bound, provided every attempt reaches the check after a bounded interval; the
timed wait uses a real deadline that spurious wakes do not restart; mutex
reacquisition, transport submission and callbacks between checks cannot block
indefinitely; the check observes the **mount-owned authority** rather than a
flag set only at unmount; and outer callers do not restart after terminal
failure. The bound is *remaining wait + bounded local work + scheduling delay*,
not a hard one-second wall-clock guarantee under starvation.

> I would therefore revise the quoted "wake the waiters" prescription: make
> waiters **locally cancellable with an explicit bound**; waking is one
> mechanism. Lack of a broadcast is not, by itself, a defect in a proven bounded
> polling loop.

What a top-of-loop check does **not** cover is success:

```
check OPEN
submit / wait
authority closes
grant arrives
return success without another authority decision
```

Closure-aware handling is needed at request admission, grant completion, retry,
**and successful acquire exit**, synchronised with closure rather than observed
independently. A grant that wins the completion race before closure may still
become unusable, which is why the mutation gate remains necessary; a grant
accepted after closure must not revive the request.

Mechanism: one terminal cancellation state integrated into the common
pending/wait machinery, using the existing protected pending registry rather
than new per-call-site lists. Registration and closure must be synchronised so
that a waiter registered before closure is cancelled and a waiter arriving after
closure sees failure instead of sleeping. A broadcast without a terminal
predicate is not sufficient — the waiter just sleeps again.

> Aborting a caller's wait and safely reclaiming the underlying object are
> different operations.

### 4. Membership epoch and authority incarnation are different questions

The existing `pend->request_epoch` answers "does this reply belong to the
applicable DLM membership generation". The new question is "does this request
still belong to a live local authority incarnation". Local authority can close
while membership deliberately stays unchanged — precisely the case the existing
check cannot see. Do not conflate them to reuse a field, and do not locally bump
the membership epoch as a substitute.

A CLOSED latch is sufficient, without an authority field on the wire, **if** the
object never reopens, pending requests and callbacks retain a reference to that
exact object, all success paths honour CLOSED, and old replies cannot be
misassociated with requests in a replacement context. Reused node slots, request
counters, resource names and surviving transport traffic all need explicit
consideration; a mount/incarnation identifier is the straightforward answer
where existing identities do not already prevent it.

### 5. CLOSED does not mean "holds nothing" — and there may be a liveness cycle

> CLOSED means this incarnation lacks permission to continue productive
> operations. It does not erase outstanding I/O, retained locks, journal
> ownership, or recovery exclusion obligations.

| property | withdrawn state |
|---|---|
| local productive authority | CLOSED |
| local pending acquires | fail terminally |
| ordinary local writes | forbidden |
| outstanding recovery obligations | retained |
| recovery / quarantine exclusion | potentially retained |
| control-plane participation | only as explicitly permitted |

So failing this mount's waiters and preserving remote-visible exclusion until
recovery are compatible and need not end at the same instant. **But the sender's
intent does not establish renewal semantics.** If the renewal that keeps running
after withdrawal supplies or extends the authority just closed, it conflicts,
whatever the comment calls it. It is sound only if the protocol gives it a
narrower receiver-side meaning — "this incarnation remains withdrawn; preserve
the specified recovery exclusion; this does not restore productive authority" —
and that distinction must exist in receiver behaviour, not only in the sender's
explanation. A delayed pre-withdrawal ACTIVE renewal must not reverse WITHDRAWN
within the same incarnation, and peers must not read renewed membership as
evidence that recovery is unnecessary.

> Preventing remastering is not necessarily preventing conflicting grants by the
> existing master.

**The concrete liveness hazard, and it deserves its own audit:**

> Renew membership until replay is complete, while replay starts only after
> membership expires. If those are the actual predicates, you have a cycle. A
> healthy withdrawn node can renew forever and prevent the recovery that would
> let it stop renewing.

Explicit answers are required to: who performs replay, under what independently
valid recovery authority; what makes replay eligible despite the retained
freeze; and what ends or overrides the freeze, including if the withdrawing node
dies midway. If the freeze outlives mount teardown, its state needs a retained
or recovery-owned lifetime — not access through a freed mount object.

## What to measure

> Your existing read-stall experiment is useful, but **shorter read latency
> alone is not the deciding measurement.** It can conceal an accepted late
> grant, a caller retry, or cleanup that remains stuck.

Instrument the state transitions, correlated by mount/authority incarnation, DLM
epoch, request id, resource and caller: authority deadline and CLOSED
publication; filesystem shutdown-state publication; request admission and wait
entry/exit; each retry; grant receipt **and the grant acceptance decision**;
terminal pending completion and errno; acquire return; final caller return and
cleanup completion.

Five intervals, measured separately, because a small value for one proves
nothing about the others:

1. deadline → CLOSED publication
2. CLOSED → pending request terminal
3. CLOSED → acquire return
4. CLOSED → caller return
5. CLOSED → teardown / resource reclamation

Six arms:

- **A. Preserve the existing recovery behaviour.** Authority OPEN, peer recovery
  blocked: the non-fallible path must not regain the old shutdown storm.
- **B. Terminal cancellation without peer help.** Close authority while replies
  are impossible; both fallibility classes, including a genuinely dirty
  transaction; bounded local termination and shutdown-safe unwind with no peer
  acknowledgement.
- **C. Same-membership-epoch late grant.** Membership unchanged, local authority
  closed, then a delayed grant bearing the otherwise-correct DLM epoch. This is
  the discriminating test the existing stale-master test does not cover.
- **D. Closure races.** Closure injected before wait registration, immediately
  after it, during retry/resubmission, and against grant acceptance. Look for
  lost cancellation, double completion and leaked references.
- **E. Replacement lifetime.** After teardown/remount, deliver an old reply: it
  must neither complete a new request nor touch freed state.
- **F. Freeze and recovery.** The peer's actual interpretation of post-closure
  renewals; preserved recovery exclusion *and* the defined path to
  replay/release, including failure of the withdrawing node.

For the success arms, distinguish the acceptance linearization point from the
moment a woken thread happens to return; and distinguish I/O admission from
completion, because pre-closure submitted I/O can complete later and its
interaction with takeover is a quiescence obligation that condvar cancellation
does not solve.

## The bottom line, in its own words

> The correction I would prioritize is terminal authority cancellation in the
> core acquire/completion machinery — not another peer-failure special case. A
> one-second polling check can be a valid first implementation of the wait
> bound. It is not a substitute for shutdown-safe unwind, closure-aware grant
> acceptance, or explicit freeze/recovery semantics.
