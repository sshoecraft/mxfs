---
name: technique-a-kernel-return-value-can-be-a-matched-witness-by-one-at-a-time-serialization-even-when-nothing-checks-the-tag
description: TECHNIQUE (s100): libiscsi's TMF success is trustworthy per-operation although iscsi_tmf_rsp never checks the ITT — the proof is the one-TMF-per-sess…
metadata:
  type: feedback
tags: [fencing, scsi, iscsi, witness, kernel-audit]
---

# A return value can be a matched witness without any tag matching

Asked whether `ioctl(SG_SCSI_RESET, DEVICE|NO_ESCALATE)` returning 0 proves
*this* LU RESET was answered by the target, the obvious place to look is tag
matching. It is not there, and concluding "therefore it is only a session-wide
inference" would have been wrong.

`iscsi_tmf_rsp()` (`drivers/scsi/libiscsi.c:996-1014`) does **not** validate the
Initiator Task Tag. It checks `session->tmf_state != TMF_QUEUED → return` and
then applies whatever response arrived.

The per-operation association is supplied by serialization instead, and it
takes three separate reads to establish:

1. Every TMF entry point takes `eh_mutex` then `frwd_lock` and refuses unless
   `tmf_state == TMF_INITIAL` — LU reset `:2536`, abort `:2422`, target reset
   `:2698`. One TMF outstanding per session, so no other request of ours exists
   for a response to belong to.
2. A timed-out TMF does **not** return to `TMF_INITIAL` on a live connection:
   `iscsi_eh_device_reset` answers `TMF_TIMEDOUT` with
   `iscsi_conn_failure(conn, ISCSI_ERR_SCSI_EH_SESSION_RST)` (`:2552-2555`), and
   the send-failure path fails the connection too (`:1922-1927`). So the
   stale-late-response-meets-new-request window never opens on a connection that
   later reports success.
3. `iscsi_exec_task_mgmt_fn` returns `-ENOTCONN` on `age != session->age ||
   state != ISCSI_STATE_LOGGED_IN` (`:1945-1957`), so a reconnect across the
   wait is reported rather than swallowed.

## The general lesson

When an API gives no explicit correlator, look for an enforced
**one-at-a-time** invariant before concluding the result is ambiguous. A mutex
plus a state gate can be exactly as strong as a tag — but it is strong for a
different reason, and that difference is load-bearing:

- A tag keeps working when concurrency is added.
- A serialization invariant silently weakens to an inference if a later version
  ever allows two in flight, **with no change to the value the caller reads**.

So anything minting durable evidence from such a value must pin the versions it
was audited against and refuse the rest. Write down *which* invariant the claim
rests on, not just that the claim holds.

## Auditing a version you do not have

The fleet ran 6.8.0-101-generic; only `/src/linux` (7.1.0-rc7) has full source,
and downloading kernel source is forbidden here. The distro
`linux-headers-<ver>` package does ship `include/scsi/libiscsi.h`, which carries
the state machine's declarations. Comparing them (`TMF_*` enum, `eh_mutex`,
`ehwait`, `tmhdr`, `tmf_timer`, `tmf_state`, `lu_reset_timeout`, `frwd_lock`)
found them identical at identical line numbers in both trees. That is a
structural cross-check worth doing and worth reporting as exactly that — it is
not a body-level audit of the deployed tree, and saying so is the difference
between evidence and a claim.
