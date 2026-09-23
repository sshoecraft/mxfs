---
name: trap-killing-the-page-authority-makes-the-acquire-fail-fast-so-a-stalled-transition-lap-must-keep-that-authority-alive
description: TRAP (s133/s134): a page transition needs the page's MASTER alive, not its authority — a dead member keeps mastership until its recovery completes.
metadata:
  type: feedback
tags: [dlm, harness, vacuous, page-transition, mastership]
---

# A refused page transition needs the page's MASTER alive — not its authority

`tests/nonfallible_transition_stall.sh` exists to measure
D-A-STALLED-PAGE-TRANSITION-IS-AN-UNBOUNDED-WAIT-FOR-A-NON-FALLIBLE-CALLER.
Lap s130c (0.89.54) reported `VACUOUS reason=no-transition` with
`transition-wait=0 stalled=0 sb-lock-at-put_super=1`, and its whole window held
one line for the probe:

    mxfs: P-SB-SUMMARY-LOCK slot=1 rc=-107 epoch=0 at=put_super

`-107` is `-ENOTCONN`. The s133 reading of that was "the lap killed the party
that could have refused". **That is not the mechanism.** s134 read the paths and
the mechanism is mastership:

* Mastership is **page-aligned over the sorted ACTIVE node list** —
  `mxfs_dlm_resource_master` → `dlm_page_master_locked`, `dlm/dlm.c:9320`. It is
  not a property of the ledger page's authority and is not chooseable by the
  harness: for a given view, the summary key's page has exactly one master,
  fixed by the node ids.
* A dead member **does not leave that view until its recovery completes**
  (`dlm/dlm.c:6601` states it), and this lap deliberately PARKS the recovery at
  SNAPSHOTTING with `rman_inject=1`. s130c's prover logged **no
  `P-TAUTH-TAKEOVER` line at all** — the departure worker never ran — so the
  destroyed victim was still the master.
* A request whose master is a dead-but-in-view node takes the **remote** path
  (`dlm.c:6593`) and fails fast: `-EHOSTDOWN` from `P-RBLK-DENY-DEAD-MASTER`
  when the master's recovery reads as blocked, otherwise the send's own
  `-ENOTCONN`, which the retry loop spends its budget on and returns
  (`dlm.c:8078`).

## What the wait actually needs

`MXFS_DLM_RETRY_TRANSITION` has two producers and **both need a live master**:

* (a) the master is someone else and answers `MXFS_ERR_AUTH_TRANSITION`
  (`P960-AUTH-TRANSITION-TX`, `dlm.c:10350`) because its own
  `dlm_ledger_prepare` parked with `-EINPROGRESS`;
* (b) the master is this node and `dlm_page_acquire` parks with `-EINPROGRESS`
  itself — its on-demand takeover of the dead authority was refused
  (`dlm.c:2779-2787`) or the bootstrap node it asked has not answered
  (`dlm.c:2869`).

`dlm_page_ensure_mine` → `dlm_page_acquire` is reached **only on the local-master
path**, so "the page's authority is a dead incarnation" is worth nothing unless
the node that MASTERS that page is up.

The schedule that satisfies both: kill the victim with the guard parked below
IMAGES_REPLAYED, then **bring the victim back as a NEW incarnation**. The page's
durable authority is then `{victim, inc A}` — dead by the slot map and named by
a standing `RECOVERY_GUARD`, which `v5_recovery_judging_cb` protects "at any
owner, lease state or age" — while the node that masters the page is alive and
can answer. Whichever of the two nodes that master is, the other's `put_super`
meets (a) and the master's own meets (b), so the lap need not know which.

## The general lesson

Before a lap kills the node that holds the thing under test, ask **which node
must answer** for the request, not only which node owns the resource. On a
two-node cluster "orphan the resource by killing its owner" also deletes the
master that would have routed the request, and the acquire then fails on the
transport — a bounded error where the lap wanted an unbounded wait, and a
vacuum where it wanted a measurement.
