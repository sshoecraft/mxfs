---
name: trap-a-hang-site-can-be-gated-out-of-a-release-by-its-transport-and-only-every-call-sites-gate-says-so
description: TRAP (s129): mxfs_iclus_lock's unkillable wait_event is real but CAW-only; the scoping came from reading all five call-site gates, not the wait.
metadata:
  type: feedback
tags: [scoping, reach, hang, iclus, transport, defect-queue]
---

# A hang site's severity and its REACH are two different reads, and the second one is per call site

`mxfs_iclus_lock` (`xfs/xfs_mxfs_dlm.c:64563`) is the worst-shaped wait in the
tree: a plain `wait_event`, `TASK_UNINTERRUPTIBLE`, untimed, not killable, whose
condition is

    !READ_ONCE(ic->busy) && (mxfs_iclus_admission_open(ic) ||
                             READ_ONCE(ic->rel_state) == MXFS_RELSTATE_WEDGED)

— naming neither `xfs_is_shutdown` nor the authority. Reading the wait proves it
can hold a caller forever. It proves **nothing about which release it blocks.**

It is reachable only on the CAW transport. `mxfs_iclus_routed()`
(`xfs_mxfs_dlm.c:34839`) requires `mxfs_v5_dlm_transport_caw()`, and
`icluster_dlm` is a load-time `0444` param declared as a bare `int` (default 0)
on top of that. On TCP the site never executes.

## The part that actually took the work

Four of the five call sites do not name the predicate locally, and one ungated
caller would have reopened the whole thing:

- two go through `mxfs_dlm_iclus_covered()`, a non-static twin that just returns
  `mxfs_iclus_routed(ip)`;
- one has an explicit `if (mxfs_icluster_dlm && mxfs_v5_dlm_transport_caw(...))`;
- one has **no local transport gate at all** — its only nearby condition is an
  unrelated knob (`pub_defer_claim`, default 1) — and is gated solely by sitting
  inside an `if (pub_routed)` block 96 lines up, where `pub_routed` was assigned
  `mxfs_iclus_routed(match)`. Establishing that meant enumerating every reference
  to `pub_routed` (four) to show there was no other way into the block.

## The rule

Read the wait to grade the hazard. Read **every** call site's gate to grade the
reach. A single call site, or the predicate you happened to find first, will
give you a confident answer that is wrong in either direction — and scoping a
record to the wrong release either ships a hang or blocks a release on a site
that cannot run.

And scoping is not a disposition: the site stays open and dangerous for the
configuration it *does* reach. Here it remains a live unkillable-hang hazard for
any CAW release, where its fix needs a terminal term in the condition **and** a
waker on the closure path — a term alone cannot wake a task nothing signals, and
the only sweep over all inode clusters runs from `put_super` and `kfree`s each
object without ever waking its waiters.

## Related, same session

A brace-depth scan for `for(;;)`/`while(1)` around a sleep produced 16
"unbounded-shaped" loops in `dlm/`. All 16 were read and **all 16 terminate** —
the exits are inside the bodies. A shape scan locates candidates; only reading
each one dispositions it, and the false-positive rate here was 100%.
