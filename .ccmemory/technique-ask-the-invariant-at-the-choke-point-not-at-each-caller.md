---
name: technique-ask-the-invariant-at-the-choke-point-not-at-each-caller
description: TECHNIQUE (sess571, D-0945): an invariant enforced at N callers has N chances to be forgotten; instrument the 1-2 primitives they all funnel through.
metadata:
  type: project
tags: [rule4, d0945, instrumentation, dlm]
---

# Ask the invariant at the choke point, not at each caller

## The shape of the bug this catches

D-0945: the poison gate ("an incarnation may not release an on-disk grant once
its log has shut down") was implemented at each of the mount layer's release
wrappers in `dlm/v5_mount.c`. Eight of them. Seven had it. `mxfs_v5_dlm_inode_
unlock_free` had it on its CAW arm and **nothing** on its TCP arm.

It was found by reading the file — after the damage had already been chased
back through a survivor's refused replay, a quarantined AG 0, and an unmountable
victim. Reading is also what had missed it for as long as it existed. That is
not bad luck: **a caller nobody thinks of has no missing gate to notice.** The
audit's completeness depends on enumerating the callers, and the enumeration is
the thing that failed.

## The move

Find the 1-2 primitives every caller funnels through and ask the question there.
For releases that is `mxfs_dlm_unlock_gen` and
`mxfs_dlm_send_unconditional_release` in `dlm/dlm.c`.

The lower layer usually cannot answer the question itself (dlm.c knows nothing
about `depart_state`). Plumb an oracle callback — the file already had the
pattern: `recovery_blocked_cb`, `node_live_cb`, `refused_owner_cb`, all reading
`ctx->cb_data`. Added `local_poisoned_cb` next to them (0.75.115).

## LOG, do not refuse

Critical: the choke point must not enforce. Whether releasing while poisoned is
a defect **depends on which path it is** — `mxfs_dlm_caw_purge_node` releases a
DEAD PEER's slots from a survivor, the opposite operation, and gating it would
be a new defect. So the probe names the call site
(`__builtin_return_address(0)` + `%pS`, the pattern already used at dlm.c's
P52-GRANT-FREE) and the disposition is made per site with evidence in hand.

    P945-RELEASE-WHILE-POISONED fn=unlock_gen type=1 ino=132 ag=0
                                comm=kworker/2:1 n=1 caller=<symbol>

The refusals stay at the wrappers. The choke point says where one is still owed.

## Why this is the RULE 4 move

It converts "read every caller and hope" into a measurement. The owed audit item
on D-0945 was "the same question for the release paths that do not live in
dlm/v5_mount.c" — an unbounded reading task. The probe answers it from one death
lap, and keeps answering it for callers added later.

## Generalizes to

Any invariant of the form "operation X is forbidden while state S holds", where
X has many entry points and S is known only to a higher layer. Publish side of
the same defect (a grant installed on one transport and not the other) is the
obvious next application.
