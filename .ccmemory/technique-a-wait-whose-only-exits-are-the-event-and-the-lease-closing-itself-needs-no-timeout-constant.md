---
name: technique-a-wait-whose-only-exits-are-the-event-and-the-lease-closing-itself-needs-no-timeout-constant
description: TECHNIQUE (s103): the post-reset barrier waits for a heartbeat with no chosen bound — the authority lease already bounds it, and any number would be…
metadata:
  type: feedback
tags: [timeouts, authority-lease, lu-reset, design]
---

# A wait bounded by a lease needs no timeout constant

0.89.32, `mxfs_v5_dlm_lu_reset_barrier()` in `dlm/v5_mount.c`.

After issuing an LU-scope reset, the issuing node must establish that its own
coordination I/O converged and that its storage-authority lease survived. The
implementation waits for a heartbeat ISSUED AFTER THE RESET TO LAND:

```
for (;;) {
    if (dl->auth->last_ok_ms > reset_issued_ms) { beat_landed = true; break; }
    if (!mxfs_disklock_authority_ok(dl)) break;      /* the lease closed itself */
    mxfs_pal_sleep_ms_interruptible(HB_INTERVAL_MS / 4);
}
```

**There is no timeout parameter and there must not be one.** The loop has
exactly two exits, and the second one is the bound: `mxfs_authority_ok()`
evaluates the deadline at every call and closes the epoch itself when it has
passed, whether or not any timer ran. So the wait cannot exceed the lease.

A chosen number would be wrong in both directions:

- shorter than the lease → refuses a node that still holds authority, turning
  a slow beat into a lost mount;
- longer than the lease → the node is asserting its own liveness past the point
  its peers are entitled to give the resource to someone else, which is the
  "manufacture apparent liveness" fix the design consult rejected.

The same loop also carries the convergence proof for free, and that is the part
worth reusing: the heartbeat sector is written through a **single-outstanding
synchronous** compare-and-write, so a fresh beat *cannot* land until the beat
the reset stranded has been resolved. Observing the new one IS observing the
old one finish — no drain, no generation filter that would have to reject a
completion, and nothing that can block the reset, an abort, an EH retry or
transport recovery.

**Generalise:** when the thing you are waiting for is also what renews a lease
you hold, and the lease is checked at the point of use rather than by a timer,
the lease is the timeout. Look for that shape before reaching for a constant.

Measured: `tests/lu_reset_barrier.sh` s103b — held in 2523 ms healthy, held
after waiting 12598 ms with the beat paused under the lease, refused after
28228 ms with it paused past the lease.
