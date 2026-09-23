---
name: design-the-three-routes-to-a-retirement-witness-and-why-only-a-matched-target-response-counts
description: DESIGN (Astra s82): witnessed LU RESET is the general fix, early PREEMPT AND ABORT an optimisation, refusal the fallback; an EH success is not a witn…
metadata:
  type: project
tags: [fencing, scsi, lu-reset, design-ruling, retirement]
---

# What may authorise replay when the victim's registration is already gone

Full ruling: `docs/rulings/retirement-witness-routes-lu-reset-early-preempt-or-refuse.md`
(Astra, session 82), for the top-of-queue record
`D-BOOT-SUCCESSION-CERTIFIES-...-NO-TASK-RETIREMENT-WITNESS`.

**Ranking: implement the witnessed LOGICAL UNIT RESET as the general mechanism,
keep the early PREEMPT AND ABORT as an optimisation, and make refusal the
terminal fallback.** A qualification built from probe laps that saw no late
write does not meet an integrity bar; falling back to it leaves the defect
intact.

## The four things any route must establish

Admission exclusion; retirement of already-accepted work; control of the
**survivor's own** queued commands and retries; and a recovery that tolerates
partial pre-retirement effects. Exclusion alone does not retire. Retirement
alone does not exclude. A reset does not make an interrupted write
transactional.

## The witness is the matched response, never the return code

"The ioctl/handler/EH returned success" is not the event. The event is: *for
this request, on this transport-session incarnation, the initiator received a
successful LU RESET task-management response from the target, for the specified
LU.*

On iscsi_tcp the mapping is favourable and is readable in `/src/linux` rather
than assumed: `iscsi_eh_device_reset()` returns SUCCESS only via
`session->tmf_state == TMF_SUCCESS`, and `iscsi_tmf_rsp()` sets that only on
`ISCSI_TMF_RSP_COMPLETE` in the target's TMF response PDU; a timeout returns
FAILED through `iscsi_conn_failure()`, and a session that is not LOGGED_IN
returns FAILED without sending anything. **Re-audit that against the exact
deployed kernel before relying on it.**

Capture with the certificate: stable target and LU identity (never `/dev/sdX`),
the function requested, the LUN and initiator task tag, session/connection
identity and incarnation (to reject stale responses and tag reuse), the matching
Function Complete, and the fencing epoch and admission generation it was issued
under.

## The collateral is a prerequisite

The same handler then calls `fail_scsi_tasks(conn, lun, DID_ERROR)` — **our own**
outstanding commands to that LUN are failed. Gate the survivor's submissions at
their producers (writes, writeback, journal, outstanding block requests,
deferred submissions, retries); freezing a queue is not draining it. If those
aborts make the filesystem panic, shut down or block forever, the route has not
met the operational bar even when the target-side retirement was valid.

## What MXFS does not have

Every MXFS command goes out through `scsi_execute_cmd()`; there is no
task-management path at all. `scsi_ioctl_reset()` is static and reached from
`scsi_ioctl()` with an `int __user *`, and `scsi_try_bus_device_reset()` is not
exported. **Fabricating a `scsi_cmnd` to call the host template's
`eh_device_reset_handler` directly is ruled out** — its locking, recovery state,
queue handling and calling-context assumptions matter. This needs a new,
fence-specific interface.

## Why the fast path cannot simply be tuned into existence

Measured on this rig: the disklock death window is 31 × 2 s = **62 s** with no
sleep between the expiry callback and the PREEMPT AND ABORT, the TCP path waits
a 40 s grace, and the QNAP purges the registration **30–46 s** after the cut. So
detection lands after the registration is gone, by about 30 s. There is no
two-phase "capture the abort scope now, execute later". What is legitimate is
separating storage-ownership revocation from declaring a machine dead — which
requires designing how a live, falsely fenced node behaves when it loses access
without corrupting, panicking or shutting down.

A conditional fast path is worth having only if **losing is safe**: win → scoped
abort, lose → witnessed reset, neither → refuse.

## No ordinary CDB supplies the missing fact

There is no command by which one initiator can ask whether a historical,
possibly nonexistent nexus has any outstanding work. PR IN reports reservation
state. TEST UNIT READY, reads, FUA reads, COMPARE AND WRITE and SYNCHRONIZE
CACHE do not supply it — a cache synchronisation is not a cross-nexus
task-retirement barrier. CLEAR TASK SET and an ORDERED cross-nexus barrier are
genuine alternatives **only** after establishing the LU's task-set model: with
per-nexus task sets, clearing ours says nothing about the victim's.
