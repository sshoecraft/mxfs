---
name: trap-a-join-time-flush-that-races-the-local-workload-and-answers-with-a-shutdown-is-the-data-loss
description: TRAP (sess584, D-0959): the incumbent's peer_joined flush ran 5 destage rounds on a protocol thread against its live workload, never converged, and f…
metadata:
  type: feedback
tags: [D-0959, join, membership, freeze, settle-gate, design]
---

# A bounded "drain then invalidate" at a membership transition must quiesce the writers, never race them

**Measured (sess584, s584c, 2 nodes/TCP, 0.83.3).** `mxfs_dlm_peer_joined_flush` ran on the incumbent's discovery/accept thread: 5 rounds of log force + AIL push + cached-view invalidation. With a create/append loop running, each walk found un-destaged AGI/inobt/finobt buffers (`P47-INVAL-SKIP-INAIL`, "2 AGs retained 7 buffers, 1 AG had live holders"), the fifth round called `xfs_force_shutdown` (`P232-INVAL-STUCK`), the create got EIO, the node declared voluntary death, the peer fenced it and replayed its slice. Every appended line in 32 files (page cache, never written by the metadata-only flush) and the entries of 34 directories were gone, and the peer's own synced adds to 3 directories too.

**What a first join must guarantee** (design consult, Astra, sess584): before the newcomer can use shared state under a grant, the incumbent's grant-less modifications are durable, its cached views dropped, and no further grant-less modification can occur; and the newcomer must not take a grant of ANY mode (PR included — a shared read served early is a stale base for the EX that follows, and no BAST can fix it because the incumbent held nothing) until positive readiness, never on a timer.

**Shipped in 0.83.4** (docs/join-transition.md): `freeze_super(FREEZE_HOLDER_KERNEL)` on the incumbent (sync_filesystem writes file data; xfs_fs_freeze quiesces the log), views dropped including clean dir/bmbt blocks, view installed and `ever_multi` set UNDER the freeze, thaw; all on a per-ctx join worker with the peer registered only after prepare; settle gate covers PR and is fail-closed while a live member's beacons still carry another view. Measured: freeze 104 ms, no loss.

**Lessons.**
- A retry-bounded flush racing the workload that dirties what it flushes cannot converge; the answer to "not converged" is "peer stays unadmitted, retry", never a shutdown. A join preparation taking too long is not a corruption.
- Log force + AIL push do not write file data. Any drain that must make a node's state visible to a peer needs `sync_filesystem`/`freeze_super` semantics.
- A view-hash beacon confirmation only orders what is gated on it: gating EX and not PR left the read side open.
- Do not freeze from the lease UDP or TCP accept thread; queue to a worker and register the peer only after the freeze succeeded, so no other refresh path can install the view early.
- The long-term shape is removing the never-multi bypass (lone node takes grants from itself, as a sole survivor does since 0.83.3); two preconditions: master handoff incorporates existing holders before any conflicting grant, and land-before-release includes file data.
