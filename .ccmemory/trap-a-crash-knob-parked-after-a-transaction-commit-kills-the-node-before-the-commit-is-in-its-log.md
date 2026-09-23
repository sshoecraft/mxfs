---
name: trap-a-crash-knob-parked-after-a-transaction-commit-kills-the-node-before-the-commit-is-in-its-log
description: TRAP (sess614, D-FOREIGN-SLICE-INTENTS-ABANDONED custodian-kill): a hold taken right after xfs_trans_commit parks with the commit still in the CIL; t…
metadata:
  type: feedback
tags: [harness, knob, durability, log-force, trap]
---

# A crash knob parked after a commit lands the crash BEFORE the commit

## What was measured (s614c, tests/evidence/20260913T043857Z_intents2tcp_s614c)
`mxfs.dbg_obl_engine_hold_ms` held the obligation engine after entry 0's
`xfs_trans_commit` so a virsh-destroy inside the hold would leave the successor
one extent already freed (the FULL branch of the takeover).  47/48 assertions
passed; the one FAIL was "successor found entry 0 FULL": the successor read
entry 0 EMPTY and freed it again.  `xfs_trans_commit` only hands the items to
the CIL; nothing pushed it to an iclog in the milliseconds before the msleep,
so the destroyed custodian's journal slice carried no trace of the commit and
the replay of that slice landed nothing.  (Correct behaviour for the design —
both branches are idempotent — but the branch the lap exists to measure was
never reached.)

## The rule
A test knob that stages a node death "after X committed" must make X durable
itself (`xfs_log_force(mp, XFS_LOG_SYNC)`, or whatever the path's own
durability point is) before it parks, or the death lands on the other side of
the commit and the lap silently measures the trivial branch.  Related:
`trap-mxfs-slice-holds-only-last-txns-destage-kick-crash-tests-need-target-txn-last`
(the slice keeps only the last few transactions) and
`technique-when-the-defects-trigger-is-unreachable-make-its-final-verdict-unconditional-under-a-knob`.

## How it hid
Every other assertion in the lap passed, including "freed + already_free ==
census extents", because re-freeing an EMPTY extent is the same end state on
the platter as skipping a FULL one.  Only the per-branch assertion saw it.
