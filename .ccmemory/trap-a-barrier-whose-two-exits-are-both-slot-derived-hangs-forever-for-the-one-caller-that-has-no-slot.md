---
name: trap-a-barrier-whose-two-exits-are-both-slot-derived-hangs-forever-for-the-one-caller-that-has-no-slot
description: TRAP (s111): the post-LU-reset barrier waits on the disklock heartbeat and the slot lease; a whole-cluster bootstrap owner has claimed no slot, so bo…
metadata:
  type: feedback
tags: [lu-reset, bootstrap, hang, authority-lease]
---

# A wait bounded by a lease is unbounded for a caller that holds no lease

`mxfs_v5_dlm_lu_reset_barrier`, `dlm/v5_mount.c:19962`. The loop is deliberate
and well argued — two exits, no chosen constant, documented at length:

```
for (;;) {
    beat_ms = dl->auth->last_ok_ms;
    if (beat_ms > reset_issued_ms) { beat_landed = true; break; }
    if (!mxfs_disklock_authority_ok(dl)) break;   /* the lease closed itself */
    mxfs_pal_sleep_ms_interruptible(MXFS_DISKLOCK_HB_INTERVAL_MS);
}
```

Both exits are **derived from a claimed heartbeat slot**. `last_ok_ms` is
stamped by the disklock heartbeat service, which starts at
`mxfs_disklock_start_heartbeat` — after the slot claim. The lease is the
slot's.

The whole-cluster bootstrap owner has **no slot by design**: its own log line
says so — *"provisional bootstrap owner; no slot, no grant, no filesystem
write until RECOVERY_COMPLETE"*. It fences at phase 3 before any claim. Its
only liveness service is `v5_boot_hb_fn` (`:3919`), which calls
`mxfs_bootstrap_heartbeat` — it beats the **bootstrap record**, never the
disklock sector and never `dl->auth`.

So for that one caller the loop has no exit at all. Measured s111a
(`tests/evidence/20260921T025611Z_bootfull/test2.cdmesg`): the file's last line
is `P307-LURESET-CONVERGE converged=1` at kernel 190.955 — which is the
`mxfs_scsipr_lu_reset_converge` call immediately *before* the loop — and there
are **zero lines above timestamp 200** in a capture that ran to ~360 s. The
mount never returned; `timeout 240 mount` could not reap it.

## What made it diagnosable in one pass

`P307-LURESET-BARRIER` is logged **unconditionally after the loop, on both
outcomes** (`:20010`). Its absence is therefore not ambiguous: it is proof the
loop never exited. A barrier that logged only its refusal would have left
"never entered" and "never left" indistinguishable, and the same capture would
have proved nothing.

## The generalisation

A wait justified by "the lease is the timeout" is only bounded for callers
that hold that lease. Before reusing one, enumerate its callers and ask which
of them holds the thing each exit reads. The bootstrap owner is the standing
counterexample in this tree: it deliberately holds *none* of the ordinary
per-slot state, so any helper that reads slot state silently degrades for it.

The fix keeps the shape and changes the source: for a slotless bootstrap
owner, exit on a **bootstrap** beat landing after `reset_issued_ms`, and on
`ctx->boot_hb_lost` — which is precisely "the lease closed itself" for a term.

Chronology note: the barrier is 0.89.32, the bootstrap is sess441-443. The
barrier was added under an assumption the older caller never satisfied, and
nothing re-drove the bootstrap through it on either transport.
