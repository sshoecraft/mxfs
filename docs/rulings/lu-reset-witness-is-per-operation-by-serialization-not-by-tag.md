# The LU RESET witness is per-operation by serialization, not by task tag

What may be claimed when `ioctl(SG_SCSI_RESET, SG_SCSI_RESET_DEVICE |
SG_SCSI_RESET_NO_ESCALATE)` returns 0, and why. This is the retirement witness
`retirement-witness-routes-lu-reset-early-preempt-or-refuse.md` ranks first and
says MXFS does not have; it turns out to be reachable, and this document states
exactly what it rests on so a later kernel cannot weaken it silently.

## The measurement that reopened the route

Seven laps of `tests/lu_reset_probe.sh` against the shipping 2/tcp LUN
(QNAP TS-453 Pro, `iSCSI Storage` rev 4.0):

| question | measured |
|---|---|
| does the target complete the function? | yes — `rc=0`, wall 39–42 ms with work in flight, sub-millisecond without |
| did a target TMF response PDU arrive? | yes — the session's `tmfrsp_pdus_cnt` advanced by exactly 1 on every lap (1→2→3→4→5 across consecutive laps) |
| is the session torn down by it? | no — `SID=session1 STATE=LOGGED_IN RECOV=120` byte-identical before and after, every lap |
| does it destroy the PR state it is issued under? | no — READ KEYS and READ RESERVATION byte-identical, PR generation unmoved (0x15dc, 0x15df, 0x15e0, 0x15e8), `Write Exclusive, all registrants` still held |

One live lap read back an empty key list; the next lap added a Unit Attention
absorber and read the keys and the unmoved generation intact. The post-reset
`PERSISTENT RESERVE IN` returns a reset Unit Attention once, and a reader that
does not consume it reports the absence of state that is in fact present.

## What the return value rests on

`rc == 0` from that ioctl is not a generic "the error handler coped". Tracing
the deployed path:

- `scsi_ioctl_reset()` with `SG_SCSI_RESET_NO_ESCALATE` maps to exactly
  `scsi_try_bus_device_reset()`, with no fallthrough to target, bus or host
  reset, and returns 0 only for `SUCCESS`.
- `iscsi_eh_device_reset()` returns `SUCCESS` only from `case TMF_SUCCESS`
  (`drivers/scsi/libiscsi.c:2549-2561`).
- `TMF_SUCCESS` is set in exactly one place: `iscsi_tmf_rsp()`
  (`libiscsi.c:1007-1008`), from `tmf->response == ISCSI_TMF_RSP_COMPLETE` in a
  received iSCSI Task Management Response PDU.

So the value reports a target response, not a local recovery outcome.

## The part that is NOT tag matching, and matters

`iscsi_tmf_rsp()` **does not validate the Initiator Task Tag**. It checks only
`session->tmf_state != TMF_QUEUED → return` (`libiscsi.c:1004`) and then applies
the response. Nothing in that function associates the response with the request
that is outstanding.

The association is therefore supplied entirely by **serialization**, and it
holds because of three things read together:

1. **One task-management function per session, enforced under the lock.**
   Every TMF entry point takes `session->eh_mutex`, then `frwd_lock`, then
   refuses if `session->tmf_state != TMF_INITIAL` — LU reset at
   `libiscsi.c:2536`, abort at `:2422`, target reset at `:2698`. While ours is
   `TMF_QUEUED` no other TMF can be issued on this session, so no *other*
   in-flight TMF of ours exists for a response to belong to.

2. **A timed-out TMF cannot leave a live session that a late response could be
   mis-attributed on.** `iscsi_tmf_timedout()` sets `TMF_TIMEDOUT`
   (`:1906-1907`); `iscsi_eh_device_reset()` answers that state by failing the
   connection outright — `iscsi_conn_failure(conn, ISCSI_ERR_SCSI_EH_SESSION_RST)`
   (`:2552-2555`) — and does not return the state to `TMF_INITIAL` on a
   surviving connection. The send-failure path fails the connection too
   (`:1922-1927`). So the stale-response-meets-new-request window does not open
   on a connection that later reports success.

3. **A connection or session change across the wait is reported, not ignored.**
   `iscsi_exec_task_mgmt_fn()` returns `-ENOTCONN` when
   `age != session->age || session->state != ISCSI_STATE_LOGGED_IN`
   (`:1945-1957`), which the caller turns into `FAILED`.

**The claim this supports**, and no more: *for this reset invocation, on a
session whose identity and age did not change across the call, the initiator
received and accepted an iSCSI Task Management Response carrying Function
Complete, while no other task-management function was outstanding on that
session.*

**The claim it does not support**: that the target reported *which* request it
was answering. It did not, and the kernel did not check. The witness is sound
because only one request can be outstanding — not because the answer was
matched to it.

### The consequence for the future

The witness depends on a libiscsi *invariant*, not on a protocol field. A
kernel that ever permits more than one outstanding task-management function per
session, or that returns `tmf_state` to `TMF_INITIAL` after a timeout without
failing the connection, weakens this witness to a session-wide inference
**without any change to the value MXFS reads**. Any code that mints a
certificate from this must therefore pin the kernel versions it was audited
against and refuse the ones it was not — a silent weakening is the failure mode
to design against.

### Which kernel was audited

The source read above is `/src/linux` at 7.1.0-rc7. The fleet runs
6.8.0-101-generic. The two are not the same tree, and the function bodies were
not compared line by line. What was compared is the data the state machine is
built from, in `include/scsi/libiscsi.h`: `TMF_INITIAL/QUEUED/SUCCESS/FAILED/
TIMEDOUT/NOT_FOUND`, `eh_mutex`, `ehwait`, `tmhdr`, `tmf_timer`, `tmf_state`,
`lu_reset_timeout` and `frwd_lock` are present in both, with identical
declarations, at identical line numbers (46-51, 285-290, 303, 350). That is a
structural cross-check and it is strong; it is not a body-level audit of the
deployed tree, and it is written here as the former.

## What the witness still does not give

A completed LU RESET is a **retirement** proof and only that. It is not
admission exclusion — nothing in it stops the victim, or its rebooted
incarnation, from submitting new work — it is not local-I/O control over the
survivor's own queued commands and retries, and it is not a durability or
cache-persistence statement about writes the target already completed. Those
remain separate obligations, and a certificate that folds any of them into this
one is claiming more than was measured.

## The admissibility precondition is the harder half

The reset is logical-unit-wide by design, which is what lets it reach work
whose session is gone — and which is also why it destroys bystanders. Measured
on this rig: a bystander initiator's command is aborted at the target, no
completion is ever sent, and it waits in `blk_io_schedule` inside
`__iomap_dio_rw`, in D state, with no error, no timeout and no retry, until the
node is power-cycled.

So the operation is admissible only from a sole live initiator, and
"sole live initiator" has to be **enforced**, not asserted. The following is
specifically *not* sufficient, and is the same class of environmental assertion
that the withdrawn retirement clause was:

> membership says one node, READ KEYS shows only our own key, and the rig's
> declared reach names only these two hosts.

`READ KEYS` enumerates registrations, not I_T nexuses: an unregistered
initiator can hold a session and have commands outstanding. Membership
classification does not prevent a storage login. A rebooted peer can log in
between the check and the reset — the 40 ms width of the operation narrows that
race but does not close it, because the gate has to exclude the *new*
incarnation rather than classify the old one dead.

The minimum honest gate therefore needs LUN presentation that is enforced at
the target rather than documented, an enforceable mechanism that keeps the
victim from establishing or retaining a nexus for the whole interval, the gate
held unbroken across the entire reset, every initiator port and portal and path
counted, and unknown state failing closed.

## Ordering, when this is built

1. Close all MXFS producers of shared-LUN work and stop new submissions.
2. Close the current local-I/O generation, so no pre-reset command or retry can
   be mistaken for post-reset work. Note the trap: freezing the queue and
   waiting for outstanding I/O to finish *before* the reset deadlocks exactly
   when the reset is the thing that would terminate that I/O.
3. Take and hold the sole-initiator gate.
4. Issue the reset with escalation forbidden, and require the bound witness.
5. Drain old-generation completions and retries; consume the reset Unit
   Attention, validating its sense data rather than absorbing one blindly.
6. Revalidate session identity, LUN identity, PR registrations and reservation,
   and admission exclusion.
7. Only then authorise foreign replay, in a new generation.
8. Reopen ordinary submissions after ownership and recovery are committed.

Refuse on any uncertainty in that chain. A helper timeout is **indeterminate**,
never "the reset did not happen": killing the helper does not cancel an ioctl
already executing, so the gate may not be released and a bystander may not be
admitted on that path.
