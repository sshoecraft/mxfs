---
name: ccloop-c7ee71c6-sess66-GPT-ruling-recovery-coordinator-and-pending-is-volatile
description: sess66: RULE-5 ruling on moving recovery_begin() to fence time — dedicated coordinator, not the HB thread; PLUS the proof that recovery_pending[] is…
metadata:
  type: reference
tags: [foreign-replay, recovery, descriptor, disklock, gpt-ruling, do-not-board, in-progress]
---

# sess66 — GPT ruling on the fence-time descriptor + a load-bearing code fact

Tree 0.11.409, srcversion `F696294F7C2ECCE699E08C3` (unchanged — the only
edit this session was a comment correction).  **STILL DO NOT BOARD.**
No rig cycle since 0.11.401; 8 versions of unverified change on the live
death/recovery path.

## The code fact that reframes the whole increment

`mxfs_disklock_mark_recovery_pending` (`dlm/disklock.c:1775`) does **NO
device I/O**.  It takes `ctx->lock` and sets three in-memory arrays
(`recovery_pending[]`, `pending_node[]`, `pending_epoch[]`).  The comment
in `v5_mount.c::v5_defer_slice_recovery` that claimed it "does device I/O"
was FALSE and has been corrected in-tree.

Consequences (this is why it matters, not trivia):

- The recovery-pending marker is **per-node volatile state**, not a durable
  cluster-visible reservation.  A node that never witnessed the death has
  none; if every witness reboots it is gone entirely.
- Therefore GPT's conditional in §2 below BITES: you may NOT justify the
  "no descriptor yet" window by appeal to a durable pending marker.
- **What actually reserves the slot in that window** is the victim's own
  stale `ACTIVE` sector: `mxfs_disklock_claim_slot`'s free-slot scan
  (`disklock.c:2811`) takes a slot only when it is NOT `ACTIVE` (or bad
  magic / foreign `fs_gen`).  An ACTIVE-but-not-ticking record is never
  claimable however stale.  **Any future change that lets a claimant
  reclaim an "abandoned" ACTIVE slot removes the only protection this
  window has.**
- STILL TO AUDIT (GPT explicitly demanded it, not yet done):
  `slot_unclaimed` (`disklock.c:3014`), the ADOPTED_SLICE mount path, and
  journal-slice reuse.  Prove each honours stale-ACTIVE, or add the
  ownerless `FENCED_UNCLAIMED` guard GPT describes.

## The ruling (RULE 5, gpt-5.6-sol) — binding points

**1. Placement of `begin()` — elected-dispatch acquisition via a DEDICATED
COORDINATOR.**  Not option (a) every-survivor (owner/executor split: the
CAS winner need not be the elected replayer, turning a cheap duplicate-
tolerant election into a mandatory distributed lease acquisition, and
leaving an owner that never refreshes).  Not option (c) top-of-replay-
worker (couples lease acquisition to `system_unbound_wq` starvation — the
same queue the long replay runs on).  Sequence:

    monitor thread:  fence + VERIFY fencing -> note death -> pending -> schedule coordinator
    coordinator:     revalidate {victim identity, fence state, pending, election,
                                 replay-service availability}
                     -> begin(FENCED) -> reconcile -EAGAIN -> START REFRESHER
                     -> only then queue dead_node_notify_fn

**2. Once the descriptor exists it is the AUTHORITATIVE owner election.**
Lowest-live-slot is only for choosing an initial claimant or a takeover
candidate.  A topology change must not redirect execution while the
descriptor owner is still valid.

**3. `takeover` is required NOW, for liveness** — not only at the
OBLIGATIONS stage.  If A does `begin(FENCED)` then dies, B may redo the
(idempotent) replay but cannot refresh, advance, release grants, or zero
the sector under A's ownership: the recovery is frozen at RECOVERY_GUARD
forever.  BUT: a stalled `owner_stamp_ms` proves only "I observed no
refresh", never "the old owner cannot resume".  **Safe takeover requires
the owner's session be confirmed dead AND fenced from the LUN first** — a
shorter timeout is not a substitute.  (Duplicate replay is tolerable today
because replay is idempotent; do NOT make that the contract, it breaks at
the next increment.)

**4. Refresh driver: a dedicated recovery lease keeper** (one delayed-work
queue or kthread managing all owned descriptors), owned by the DLM
coordinator.  NOT the heartbeat monitor, NOT the replay worker, NOT
`system_unbound_wq`.  Serialize `begin`/`advance`/`refresh`/takeover per
descriptor locally or your own ops CAS against each other.
Cadence: refresh 1000 ms; abandonment probe = sample, wait **6000 ms**,
sample again (the current `MXFS_RECOV_REFRESH_MS * 3` = 3000 ms is too
aggressive for a correctness lease — a delayed workqueue, device timeout
or scheduler stall exceeds it).  Treat ANY of {owner stamp, stage,
stage_seq, owner term, recovery_gen} changing as liveness, not just the
stamp.

**5. Latency:** keep the durable CAS + readback + flush OFF every monitor
thread.  The monitor does fence / note / pending / schedule.  Use a
dedicated recovery workqueue.

**6. Mount window:** do NOT acquire ownership merely because we are
lowest-live if the XFS hook is not registered, mount can still fail, or we
cannot keep refreshing after a mount failure — a live node would hold a
permanently fresh FENCED descriptor while never becoming replay-capable,
and no one could time it out because its session is alive.  **Preferred
contract: acquire ownership only when the local replay service is
registered and capable**; until then durable-pending + stale-ACTIVE
reserves the slot.  Re-run election when the hook registers, a mount
completes or fails, an owner dies, a replay-capable node joins, or a
takeover completes.  Election should prefer recovery-CAPABLE nodes.

**7. ABA / owner term — REQUIRES A WIRE CHANGE.**  Current code bumps
`recovery_gen` on takeover; GPT rules that WRONG.  `recovery_gen` is the
identity of the *recovery transaction* and must stay CONSTANT across
takeover; a separate monotonic **owner term** identifies the current
authority to execute it.  Without it there is a real ABA hole:
A/session X -> B -> A/session X leaves the same `{owner_node, owner_epoch}`
and a stale A worker looks current.  The struct has a free `uint32
reserved` at offset 72 — repurpose it as `owner_term`.  Safe to change the
format freely: no rig has EVER run a build that writes a descriptor (last
rig run was 0.11.401), so nothing on disk carries version 1.
Bind worker authorization to `{victim identity, recovery_gen, owner_node,
owner_epoch, owner_term}` and revalidate before every stage-changing or
non-idempotent operation.

**8. Other enforced rules:** `-EAGAIN` is never "someone else handled it" —
every caller reads and classifies the winner.  FENCED must mean *verified*
fencing, not "a fence was requested".  Descriptor corruption means freeze,
never fallback to stale-ACTIVE logic.  Quarantine is terminal for
ownership.  Cohort: acquire+refresh each descriptor before touching its
slice, advance each independently, never publish one slot because a
cohort-level op partly succeeded.  **The current "complete/zero, then
adopt unlinked bucket" ordering cannot survive once OBLIGATIONS_DONE is
meaningful.**

## Next session — implementation order

1. Wire change: `owner_term` at the `reserved` slot; `recovery_gen`
   constant across takeover; takeover bumps `owner_term` (+ `stage_seq`).
2. Coordinator thread in `dlm/v5_mount.c` (`mxfs_pal_thread_create`, 1 s
   loop, like `disklock_hb_fn`) owning: begin-on-elected-and-capable,
   refresh of every owned nonterminal descriptor, takeover of an owner
   confirmed dead+fenced, and dispatch of `dead_node_notify_fn`.
3. `v5_lease_expire_cb` stops calling `dead_node_notify_fn` directly; it
   fences, notes, marks pending, wakes the coordinator.
4. `mxfs_v5_dlm_recovery_complete` stops calling `begin()`; it must
   VERIFY we still own the descriptor, then `advance(IMAGES_REPLAYED)`.
5. Replay-capability gate so the mount window cannot take ownership.
6. Finish GPT's reuse audit: `slot_unclaimed`, ADOPTED_SLICE mount,
   journal-slice reuse.
7. Then a rig cycle — 0.11.402..409 has never been boarded.
