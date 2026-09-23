# A mount-owned authority, and what a live lease does not restore

Design-consult ruling (Astra, session 88, 0.89.21). It continues
`local-authority-lease-and-the-limits-of-a-software-gate.md`, whose evidence
item F — "nothing from epoch E may acquire E+1's authority" — was the question
put to it, and whose §3 required that "deferred work has to retain its
originating authority identity".

## What was brought to it

In MXFS an incarnation is a Linux mount: one `struct xfs_mount`, one DLM
context, one disklock context, one incarnation epoch drawn once. A fresh
incarnation is therefore always a fresh mount object, and old-epoch deferred
work cannot literally be handed a *different* incarnation's authority object —
the two live in different mounts.

But the alternative invariant the ruling had offered — "the old mount object is
permanently dead, never reused, and **still referenced by all its work**" —
fails on its third clause, in the ordinary unmount path. Every authority gate
read `mp->m_mxfs_dlm` and `write_admitted(NULL)` returned true, "not a
clustered mount". `put_super` clears that pointer and joins the heartbeat
thread *before* `xfs_unmountfs` writes the log cover and the unmount record.

So the proposal was: make the authority reference immortal for the life of the
mount object, rather than stamping every work item with an epoch.

## The ruling

> You found a fail-open teardown bug. It does not require old work to acquire
> E+1's authority: E's own mount changes from "clustered, authority
> constrained" to "apparently unclustered, unrestricted" when the pointer is
> cleared.

A mount-owned authority handle is a sound substitute for per-work epoch
stamping **where retained mount identity already supplies that stamping
implicitly**. The invariant that has to hold is stronger than "each mount gets
a different `xfs_mount`":

> Every operation originating in E remains bound to E's authority until that
> operation, including its callbacks and any work they generate, is finished.

An explicit epoch field on every work item is redundant only if all of these
hold:

- the work retains a valid reference to E's mount, or to E's immutable
  authority handle;
- that handle is never replaced, reset or reopened;
- the work does not resolve authority through "the current mount, context,
  device, journal slot, node ID or filesystem";
- shared coordination machinery cannot route an old response or callback into a
  newly registered context;
- mount memory cannot be freed and reused while old work still holds a raw
  pointer to it.

The last is not automatic. Embedding a handle does not create lifetime
protection: an old callback using a freed `mp` whose address has been recycled
for E+1 is both a use-after-free and an apparent authority transfer.

### Three corrections to the implementation

**Clustered-ness must be static from construction, not sticky after a
successful DLM init.** A clustered mount still initialising, or unwinding
before the DLM is installed, must not take the not-clustered bypass. The shape
is `if (!mp->m_is_clustered) return true; return authority_ok(&mp->m_authority);`
with the authority initialised to `NOT_ADMITTED` before anything can submit a
clustered mutation — and an unexpectedly missing authority failing **closed**.

**One authoritative state object, never two mirrored copies.** Maintaining
`{state, deadline}` in the disklock and a second copy in the mount introduces
publication and ordering problems specifically: a renewal completion racing a
close; an old renewal overwriting newer state; state and deadline read from
different updates; shutdown closing one copy while producers use the other.
`READ_ONCE()` supplies neither a coherent snapshot nor a lifetime.

**Negative decisions must be redirected too, not only gate reads.** "NULL the
pointer so a queued withdraw no-ops" is a warning sign. After detach, a queued
withdrawal, a fencing notification or a fatal-error callback must still be able
to close E's stable authority. Clearing the operational pointer must not
suppress a decision that invalidates the remaining lease.

## The clean unmount gets no exemption

> A clean-unmount record is not an exemption from authority. Its ability to
> suppress recovery makes a stale unmount record particularly dangerous.
> "Writing it avoids a dirty departure" is not a justification for writing
> after authority has expired.

If authority is lost before the clean-unmount protocol completes, the correct
outcome is an unclean departure handled by recovery — provided the refusal
follows proper error and shutdown completion paths, so that nothing silently
drops a necessary write and then declares the log clean, and nothing waits
forever for a completion the refusal bypassed.

Two qualifications that are not about the deadline at all:

- **An unexpired lease does not preserve rights already surrendered.** If
  publishing `WITHDRAWN` authorises a peer to replay immediately, then ordinary
  log writes after that publication are forbidden by the handoff even with
  twenty seconds left on the local deadline. The same question applies to
  anything released inside the shutdown path.
- **Local expiry is not the instant the peer fences.** The 30 s deadline is a
  conservative local stop relative to the peer's death policy; early release or
  withdrawal markers may be a different takeover trigger entirely.

On keeping the heartbeat alive through the tail, there are two defensible
designs — (1) stop renewing and finish under the remaining lease, departing
dirty if it expires, or (2) continue **renewal-only** service through the final
journal durability barrier. The second improves the odds of a clean departure
and is not required for safety if the first fails closed. It is unsafe to reach
it by moving one join, because the existing heartbeat thread can also reacquire
grants, republish old grant ownership, restart producers, or overwrite released
state with a stale full-record update. That needs an explicit draining phase
that permanently disables acquisition while allowing only renewal.

The final slot-release stamp is separately worth auditing: it must not be able
to clear or overwrite a slot that now belongs to E+1. An epoch-conditional
compare-and-write is a safe cleanup; a blind "I am leaving" write is not.

## What is permitted between grant publication and slot release

> `permitted = originating authority is live AND the teardown phase permits
> this operation AND the operation still has its required resource ownership`

MXFS enforces the first. The table the ruling gave:

| operation | remaining entitlement |
|---|---|
| a mutation requiring a surrendered AG grant | none under that grant |
| log cover / unmount record in E's retained slice | potentially permitted, while journal authority remains valid and the clean-unmount prerequisites hold |
| deferred inode / reclaim work | no blanket exemption; inspect the resources it actually requires |
| heartbeat renewal | only while E still owns the slot and renewal cannot restore surrendered rights |
| final release / withdrawal update | must be safe against ownership change and stale execution |

"Touches no AG metadata" is necessary context and not the whole argument,
because the *recovery effects* of a log write outlive the blocks it touches:
whether the record can suppress replay of work that was not safely completed,
whether it can make an earlier AG-changing transaction appear committed, and
whether a later replay of old records can conflict with the new AG owner.

The gate does not have to distinguish classes **if** it can be proved that
after grant publication the only remaining producers are permitted
journal-retirement and coordination producers; then sequencing and draining
establish the distinction. Absent that proof, an all-or-nothing lease gate is
insufficient.

## The boundary a mount-owned handle does not fix

Three different stall locations, and only the first is the handle's:

1. **before the authority check** — the handle refuses it;
2. **after a successful check, before submission** — a later close does not
   retract the earlier decision;
3. **after submission, in block, SCSI, transport or target queues** — the gate
   no longer controls execution.

Delayed *completions* can be harmless. Delayed *execution* of mutations is the
problem, and the successor needs a boundary before recovery at which every old
mutation is either completed and ordered into the state recovery will observe,
or irrevocably prevented from executing later. On a target that purges a dead
initiator's registration with its session, the disappearance of that
registration cannot itself establish that boundary.

> Thus the immortal handle can close the software fail-open hole while item F
> still fails below it.

## The evidence the ruling asks for

It rejected the counter that was proposed:

> "Admissions after detach goes from N to 0" is not the right success
> criterion. Your design intentionally permits some clean-unmount admissions
> after operational DLM detach, while the retained authority is still valid.

What must read zero:

- clustered admission through an "absent DLM means unclustered" bypass;
- admission after the originating authority closed or expired;
- work originating in E admitted using E+1's authority;
- a mutation requiring surrendered ownership admitted after handoff;
- stale release or coordination updates changing E+1's state.

And legitimate journal-tail admissions while detached and still inside the
deadline must be **traced**, not merely allowed — otherwise a fix passes by
breaking every clean unmount.

The schedules, in the ruling's order: (A) clean teardown including the detached
tail; (B) teardown stalled until expiry and teardown already closed, on both
mount-unwind paths as well as ordinary unmount; (C) the actual replay
interleaving, checked as far as a later crash/remount/recovery because a late
journal write can be invisible to an immediate byte comparison and still change
the next replay; (D) pause after admission, before submission; (E) requests
already below the gate, distinguishing execution completed before recovery from
execution after it began.

On (C) it added a qualification worth keeping: if correct mount lifetime rules
make it impossible to admit E+1 while E still holds relevant deferred work,
**demonstrate that barrier** rather than bypassing it to manufacture
overlapping mounts. The natural schedule is peer takeover while E's mount is
alive and stalled.

## The bottom line, in its own words

> The mount-owned handle is a sound substitute for per-work epoch stamping
> where retained mount identity already supplies that stamping implicitly. Fix
> initialization, negative-event delivery, synchronization, and lifetime — not
> just the five read sites. […] I would count the stable-handle change as
> closing the detach-to-unclustered bypass. I would count item F as closed only
> with an explicit handoff/execution-boundary argument […] Otherwise you have
> prevented E from borrowing E+1's authority while leaving open the different
> possibility that E's previously admitted writes execute after E+1 has
> recovered.

## What 0.89.21 implemented, and what it deliberately did not

Implemented: the separate reference-counted `struct mxfs_authority` holding the
one copy of the state; allocation by the mount before `mxfs_v5_dlm_init` and
release in `xfs_mount_free`; `m_mxfs_clustered` as a mount property set once;
a clustered mount with no authority object failing closed and counted; and the
reservation-conflict withdrawal and the withdrawal pump both closing the object
rather than reaching through the DLM context.

Not implemented, and each is in the defect queue with the measurement that
would close it: the renewal-only heartbeat through the journal barrier, the
per-resource entitlement check after grant publication, schedule (C)'s replay
interleaving, and schedules (D) and (E) below the gate.
