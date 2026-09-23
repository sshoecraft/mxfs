---
name: ruling-transport-repair-reconnect-protocol-and-the-remaining-non-fallible-acquire-class
description: Design consult ruling (Astra, sess588, D-0958 remainder): repair worker semantics, why socket-redial with acquire-only replay must not ship, write IO…
metadata:
  type: reference
tags: [ruling, dlm, tcp, acquire, transport-repair, D-0958, D-0912]
---

# Ruling: transport repair and the non-fallible acquire class (D-0958 remainder)

Consult answered 2026-09-12 (sess588), after open/getattr/read/readdir were made fallible.

## Transport repair worker
- Per-peer worker fed by the acquisition records: start/deadline, identity (lockspace, requester incarnation, acq_seq — stable across reconnect), resource/mode/authority epoch, last acquisition-specific receipt/status/grant, local protocol state, transport health (queued bytes, completed sends, inbound traffic, connection generation), repair attempts.
- Trigger: no receipt for 15 s while membership says live. A QUEUED acquisition is a different condition (legitimately blocked) — never diagnosed as a broken socket.
- STATUS answers: NOT_FOUND (matching request + current authority) → resend the SAME logical acquisition; QUEUED → record, normal contention policy; GRANTED → reconcile the exact existing grant via the normal grant protocol; NOT_MASTER/RECOVERING → existing routing/recovery; probe timeout → inconclusive.
- K consecutive NOT_FOUND is diagnostic/rate control only — never authorizes a new identity or abandonment; a delayed request can land after every one. Do not REQUIRE NOT_FOUND before repairing (a wedged connection cannot answer).
- Coalesce/rate-limit/jitter per peer; never reset acquisition deadlines; cancels before resends; the worker must not need the stuck locks or block behind the affected transaction.

## Reconnect is NOT "close socket, redial, replay pending acquires"
Missing: grants delivered to TCP but not the requester, releases accepted locally not by the master, cancels and replies, conversions, BASTs and acks; closing a socket does not erase messages already in the receiver's workqueue. Requirements: stable logical identities; an idempotent master state machine (duplicate pending → existing state, duplicate granted → same grant/token, no extra reference, duplicate cancelled → terminal absence) serialized with the transitions; grant identities on releases/conversions/recalls; a coordinated stream cutover (retire the old stream at protocol level, suppress stale callbacks, deterministic simultaneous reconnects); replay/reconcile every unresolved obligation both directions; tombstones retired by watermark/incarnation retirement, not a TTL. A naive receiver CAN double-grant. Per-resource drop faults are not repaired by reconnect (expected failure, not escalation). Leases on the same socket: promise no direct membership action, prefer make-before-break, never extend lease expiry to hide repair.

## Fallible boundaries still available
- Write path's initial IOLOCK ride: a plausible audited boundary (no I/O submitted, no dirty transaction, ordinary cleanup, error reaches a checked path, exact cancellation first); prior dirty page-cache pages don't prohibit failing a NEW write; audit upgrades/retries/DIO fallback separately — a later failure may need to return bytes written, not -EIO; IOCB_NOWAIT must not enter the 180 s wait; page_mkwrite is its own boundary (VM_FAULT_SIGBUS, folio/fault accounting).
- A namespace op that has only RESERVED a transaction can cancel it on a refused first acquire — "not logged yet" is not the proof; audit real mutations, deferred intents, quota/alloc state, joined objects, earlier rolls, cleanup needing remote locks. xfs_trans_cancel is not undo; never cancel a dirty transaction as an escape. Before child allocation nothing to unwind; after it, a specific restart/cleanup proof.
- Writeback before I/O: retain/redirty and defer, never clear dirty as success, no tight retry loop; ioend/unwritten conversion: existing machinery only; inactivation before mutation: defer preserving lifetime/reclaim exclusion; mid-dirty: no generic unwind. AG acquires: only a clean unwindable prefix may refuse/pick another AG.
- Residual sites: waiting with exclusion preserved + DEGRADED + repair is the honest completion; the 180 s refusal bound is conditional on obtaining terminal cancellation evidence.
