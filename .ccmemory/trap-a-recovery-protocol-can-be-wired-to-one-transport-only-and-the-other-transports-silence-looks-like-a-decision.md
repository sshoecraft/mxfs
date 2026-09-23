---
name: trap-a-recovery-protocol-can-be-wired-to-one-transport-only-and-the-other-transports-silence-looks-like-a-decision
description: TRAP (s110): the whole-cluster bootstrap has ONE call site and it is in the CAW branch — on TCP it never runs, and the record read that precedes it m…
metadata:
  type: feedback
tags: [fencing, bootstrap, transport, measurement-integrity]
---

# A recovery protocol wired to one transport only

**Measured s110a, 2/tcp, 0.89.38.** A concurrent whole-cluster restart (both
nodes destroyed, both powered on together, both mounts fired off one shared
wall-clock instant) left both mounts refused and both journal slices
unreplayed, with every fsync-acknowledged file unreachable and the filesystem
permanently unmountable.

## What made it look like the case had been considered

The TCP mount path calls `v5_bootstrap_setup`, which logs

    P-BOOT-STATE IDLE term=0 owner=0/0 ...

and 13 ms later the node logs `claimed heartbeat slot N`. Reading only the log,
that looks like a mount that consulted the whole-cluster bootstrap record and
concluded there was nothing to bootstrap.

It is not. `v5_bootstrap_setup` only *opens and reads the record*.
`v5_bootstrap_run` — the survivor scan, the term claim, the sealed manifest,
the fence-and-certify of every victim, the slot adoption and replay — has
**exactly one call site**, `dlm/v5_mount.c:16729`, inside the CAW branch of
`mxfs_v5_dlm_init`. The TCP branch (`:16127-16213`) goes straight to
`mxfs_disklock_claim_slot`. The comment at `:16145` says so outright: *"the TCP
transport carries its own durable authority ledger and no PR-fence bootstrap …
(bootstrap is a CAW path)"*.

## How the lap proved it rather than assuming it

`v5_bootstrap_run` logs a verdict on **every** path it can take — including the
one silent early return, which 0.89.19 gave `P-BOOT-SKIPPED` for precisely this
ambiguity, and `P-BOOT-SCAN-VERDICT` on every scan. Neither line appears in
either node's capture. That absence is the proof the runner was never entered,
and it is only available because someone had already made the function
incapable of returning silently.

**The general lesson.** Before concluding that a protocol "decided not to act",
find its call sites and check the branch they are in. A `_setup` that reads the
protocol's durable record is not the protocol running, and its log line sits
exactly where the real verdict would have been. The cheap confirmation is a
decision function that cannot return without logging — then a missing line is
evidence instead of an open question.

## The second half, for whoever wires it

Porting the bootstrap to TCP is not just moving a call. The bootstrap ADOPTS a
certified victim's slot K as its own log, and on TCP the durable authority
ledger must not let that resurrect the victim's mastership:
`struct mxfs_tauth_page_auth` (`dlm/tauth_ledger.h:127`) keys EXCLUSIVE
authority by `auth_node` + `auth_inc`, so an adopted slot cannot alias an EX
holder — but SHARED authority is slot-indexed (`MXFS_TAUTH_OP_GRANT_PR` is a
`holders[slot]` bit, `RELEASE_PR` validated by `{lineage, slot, node, inc}`),
so the adopted slot could alias the dead node's PR holder bit.
