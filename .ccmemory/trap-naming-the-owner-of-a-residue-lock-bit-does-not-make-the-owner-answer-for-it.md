---
name: trap-naming-the-owner-of-a-residue-lock-bit-does-not-make-the-owner-answer-for-it
description: TRAP (0.90.22, 4/tcp): a residue shared bit named for its slot's tenant still blocked; mounting nodes park notifications, mounted handlers release no…
metadata:
  type: feedback
tags: [dlm, tcp-ledger, notification, mount, residue, test-design]
---

# Naming the owner of a residue lock bit does not make the owner answer for it

**What happened (0.90.22, 4-node TCP, `tests/quiesce_remount_access.sh`):** the
fix that named a shared holder bit's owner from the heartbeat table did exactly
that (no holder imported without an owner in 12 laps), and the waits behind
such bits stayed: three of four mounts refused after 70 s (`v22a_inj6`), three
create bursts killed at 30 s (`v22b_lap2`, nothing injected).

**Why:** the design text said the named node "answers the notification for a
grant it does not hold".  Nothing did:

- a node that is still mounting has no notification handler until its
  post-mountfs setup, so it PARKS what it receives (`P-BAST-PARKED`), and its
  mount may be waiting for what the notifier's mount holds (AG 0 against the
  root inode);
- a mounted node's handler acts on what the filesystem holds; for an inode it
  never held it releases nothing and sends nothing.

The answer has to come from the layer that knows what the node holds without
the filesystem: the lock table (own entries survive membership changes) plus
the pending-request list.  `mxfs_dlm_answer_unheld` does that on receipt.

**How to apply:**

- When a fix depends on "the other side will respond", find the code that
  sends that response and the state it needs, before building on it.  A
  sentence in a comment is not a sender.
- A reply that can cross a request on the wire must be one the receiver can
  tell from a release of a real grant.  Here a generation value no grant
  carries made the master's existing stale-generation rule do it.
- Read a failed lap's holder tuples (`P-LKTIMEOUT-HOLDER` holder/hmode and
  `we=`) against each node's slot claim and its first touch of the inode in
  that era: a holder named for a node that has not touched the resource yet is
  residue, whatever the owner field says.
- In a user-mode mesh test, run a control and its fixed lap on DIFFERENT
  resources.  The control leaves its wait queued at the master; the same
  requester's next request is a re-send of that wait and notifies only on the
  re-fire interval, so the fixed lap measures the interval (9 s, then 2.5 s)
  instead of the fix (5 ms).
