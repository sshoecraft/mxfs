---
name: technique-a-predicate-whose-two-branches-demand-different-evidence-is-the-defect
description: TECHNIQUE: when one branch of a predicate reads first-hand state and the other can only ask membership, the weak branch silently licenses an unbounde…
metadata:
  type: project
tags: [dlm, tcp, design, predicate, hang]
---

# Diff the branches of a predicate before trusting either

`mxfs_dlm_resource_wait_is_live()` decides whether an acquire that has spent its
retry budget keeps waiting or gives up. It has two branches:

- **Local master**: walks the holder chain and returns `holders > 0 && live` —
  it will not license a wait unless a holder demonstrably exists.
- **Remote master**: `return node_live_cb(master)` — membership alone.

The two branches answer questions of completely different strength, and the
weak one licensed an **unbounded** wait. On TCP a requester cannot read a remote
master's holder table at all, so for every inode it does not master itself, "is
there anything to wait for?" was answered by "is the peer in the cluster?".

Measured consequence (2 nodes/TCP): with one inode's `LOCK_REQ` discarded at the
sender, `open()` blocked 495 s — 2.7 acquire budgets — still blocked at the end,
while the peer served its own reads in 5 ms. No error, no shutdown, no
escalation; nothing in the loop decreases, expires or escalates.

## The generalisable move

When a predicate branches on *where the authority lives*, one branch usually has
first-hand state and the other has only a message. Ask of each branch
separately: **what would have to be true for this to return true wrongly, and
what does the caller then do for ever?** A branch that can only observe liveness
must not be allowed to authorise an unbounded action; either give it real
evidence (a protocol message) or give the caller a bound.

## The fix shape that worked, and the one that was refuted

Worked: the master sends an **acceptance receipt** when it queues a remote
request (it previously queued in silence, which is indistinguishable from a
request that never arrived), the requester records it per resource, and the wait
now requires liveness AND a fresh receipt. The staleness window is derived from
the *request cadence*, never from how long a release drain takes — a drain of
any length keeps receipts flowing, so coupling them blinds the check for exactly
as long as the longest drain.

Refuted by design consult: treating an unanswered request as a liveness failure
of the peer and driving the death/fence/recovery machinery. **A requester cannot
distinguish its own broken transmit path from a broken peer** — in the very
measurement above the fault was on the requester's side — so a node that cannot
get an answer must never be able to fence the node that is answering everyone
else. Membership escalation stays behind authorised arbitration.

Also refuted as a blanket move: returning an error from the acquire. `xfs_ilock`
is void and most callers (writeback, inactivation, rolling transactions,
deferred metadata work) have no safe error boundary. Failure must be **opt-in
per call site**, registered per TASK (not per inode — two threads on one inode
would read each other's verdict), and only at a boundary where nothing is dirty
and no transaction is open. `open()` qualifies; it already had a fail-closed
`-EIO` path and the VFS already unwinds it.
