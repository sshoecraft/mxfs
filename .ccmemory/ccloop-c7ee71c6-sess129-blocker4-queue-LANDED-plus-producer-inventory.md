---
name: ccloop-c7ee71c6-sess129-blocker4-queue-LANDED-plus-producer-inventory
description: sess129: ruling blocker 4 (owed-ready queue) LANDED on 0.11.445. Plus the COMPLETE producer inventory that makes blocker 2 tractable, and blocker 3's…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess129, owed-worker, blocker4, blocker2, blocker3, stop-ship, lifecycle]
---

# sess129 — ruling blocker 4 LANDED on 0.11.445

Tree `0.11.444` → **0.11.445**, srcversion `AB4FA45D5B372180CE9E90C`, builds
clean (only the pre-existing `mxfs_dlm_lkt_dump` prototype warning + the
compiler-differs note; nothing in `dlm_caw.c`). NOT deployed; fleet stays on
0.11.440. **Still STOP-SHIP** — blockers 2, 3 and blocker 7's surviving half
remain.

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16) rather than starting
at #1, same reason as sess119–128: the DLM core is mid-landing under stacked
stop-ship rulings and sess126 set the order.

## What landed — the owed-ready queue

`ctx->lreq_sweep` (the bucket cursor) is **deleted**. `ctx->owed_q_head /
owed_q_tail / owed_q_n` replace it; `struct mxfs_caw_lreq` gains
`oq_next / oq_prev / oq_queued` (doubly linked — a retraction dequeues an
arbitrary entry from an unlock path under `lreq_lock`, and an O(queue) walk
there is charged to an XFS thread).

**THE INVARIANT** — `e is queued IFF lreq_owed_pending(e) && !e->owed_busy`.
Four helpers: `lreq_oq_remove`, `lreq_oq_push_tail`, `lreq_oq_rotate`
(remove+push_tail), and `lreq_oq_sync` which re-establishes the invariant.
**Every** owed-bit write and **every** `owed_busy` write is followed by a sync,
so there is ONE place the queue can drift. Audited: `owed_busy` is written in
exactly 2 places (`caw_owed_sweep` claim → true, `caw_owed_release` → false)
and the owed bits in exactly 2 (`lreq_owed_merge`, `lreq_owed_retract`).

It is a MEMORY-SAFETY invariant, not just a scheduling one: `lreq_gc` already
refuses on both halves of the RHS, so a queued entry can never be freed.
`lreq_gc` **also** refuses on `oq_queued` directly — redundant today, but it
turns a future weakening of the invariant into a leaked entry (already named by
P248-LREQ-LEAK) instead of a use-after-free.

Sweep: walks from the head, **bounded by `owed_q_n` at sweep start**, and
rotates an examined-but-declined entry (`clr_active`, or `!drain && now <
owed_next_ms`) to the TAIL. Those two together are the entire anti-starvation
argument — each sweep examines each entry at most once, and a declined entry
sits behind everything not yet examined. `caw_owed_release` re-enqueues at the
TAIL, so a repeatedly-failing entry cannot re-occupy the head.
`mxfs_dlm_caw_destroy` drops the queue wholesale after freeing the table
(collector already joined, nobody left to schedule).

## THE PRODUCER INVENTORY — the key fact for blocker 2

Line-verified this session. **Every obligation in the system is published from
exactly two public entry points.** Publication happens only where
`lreq_clr_begin{,_wait}` is called with a NON-NULL intent, which is exactly two
sites:

- `caw_slot_clearing` (dlm_caw.c:2581) ← called only from
  `mxfs_dlm_caw_lock` (×2) and `mxfs_dlm_caw_convert` (×1)
- `caw_drop_own_waiter` (dlm_caw.c:3462) ← called from `caw_wait_for_grant`
  (itself called only from `mxfs_dlm_caw_lock` and `mxfs_dlm_caw_convert`),
  from `mxfs_dlm_caw_lock` directly, from `mxfs_dlm_caw_convert` directly,
  **and from `caw_owed_dispatch`** — but the collector's path takes
  `lreq_clr_begin_existing`, which publishes nothing (that was blocker 5).

The other two window sites — `mxfs_dlm_caw_unlock_gen` (7508) and
`mxfs_dlm_caw_force_release_self` (8703) — pass intent = NULL. No publication.

**So "quiesce the producers" reduces to: no thread is inside
`mxfs_dlm_caw_lock`/`_convert`, and no new one may enter.** That is an
admission gate + an in-flight counter on TWO functions, not a thread-by-thread
argument about BAST/transport roles. The ruling's "if a BAST thread is both
producer and transport, SPLIT those roles" does not arise — the BAST threads
are not publishers; the XFS threads they wake are.

## Blocker 3's escalation channel ALREADY EXISTS — reuse it

The ruling wants: mark the mount failed, reject new acquisitions, force
shutdown *from a context that cannot deadlock with `lreq_lock`*, withdraw
membership so peers may reclaim. All of that is already built:

- `mxfs_dlm_shutdown_withdraw(mp)` (xfs_mxfs_dlm.c:26387) — non-sleeping,
  `schedule_work(&mp->m_mxfs_withdraw_work)`.
- `mxfs_dlm_withdraw_work_fn` → `mxfs_v5_dlm_shutdown_withdraw`
  (v5_mount.c:3958) — sets `ctx->withdrawn` (fences every new inode+AG
  acquisition), `mxfs_disklock_withdraw`, `mxfs_scsipr_unregister`,
  `mxfs_discovery_stop`.
- `put_super` NULLs `m_mxfs_dlm` then `cancel_work_sync`es the work before
  freeing the ctx, so the pointer read in the work fn is already safe.

A workqueue item is precisely "a context that cannot deadlock with
`lreq_lock`". The missing piece is only the WALL-CLOCK trigger, not the
mechanism. Note `withdrawn` also makes v5 shutdown skip `caw_release_all` and
keep the heartbeat ACTIVE — i.e. it already implements the ruling's "keep state
until peers can reclaim".

## TEARDOWN ORDER — what blocker 2 actually has to move

`mxfs_v5_dlm_shutdown` (v5_mount.c:4008) runs, in order:
4054 `mxfs_dlm_caw_release_all` → 4059 journal release → **4082 GOODBYE
broadcast** → 4088 lease stop → 4093 discovery stop → **4106
`mxfs_disklock_release_slot`** → 4111 `mxfs_dlm_caw_stop` (**the drain**) →
4131 `mxfs_pal_bdev_close_clone`.

- GOOD: the bdev closes AFTER the drain, so the LUN transport is up for it.
- WRONG: the GOODBYE broadcast and the heartbeat-slot release both happen
  BEFORE the drain — this node announces departure while its bits are still
  uncollected.
- `mxfs_dlm_caw_release_all` (dlm_caw.c:9079) is the last big producer and it
  publishes NO obligation on its own 20-retry CAS failures (sess126's "separate
  gap, same family"). It runs before the drain, so making it publish is a clean
  fix that the drain then collects.
- `put_super` (xfs_super.c:1533-1574) calls `mxfs_v5_dlm_shutdown` at 1566 but
  `xfs_unmountfs(mp)` only at **1580** — XFS is NOT quiesced when the DLM tears
  down. What closes admission is `mp->m_mxfs_dlm = NULL` at 1553 (+
  `mxfs_dlm_ag_force_release_all` at 1546); the open question for blocker 2 is
  threads already INSIDE a DLM call at that instant.

## Blocker 7 — verified, it is the false positive sess126 suspected

`lreq_owed_retract` does `if (!lreq_owed_pending(e)) { owed_fails = 0;
owed_next_ms = 0; }` on both the terminal and proven paths. Per-episode reset
is real. The SURVIVING half is `owed_since_ms` (episode start, never reset
while pending stays true) — and it is **blocker 3's** wall-clock source, so it
lands with blocker 3, not separately.

## Next session

Blockers 2 + 3 as one lifecycle change, using the inventory above. Per RULE 5,
consult GPT on the design BEFORE writing it — it touches stop/mount and a
force-shutdown path. Bring: the two-entry-point producer inventory, the
existing withdraw channel, and the teardown-order list above.

Closure for D-SAMENODE-WAITER-CANCEL-COLLISION still requires the sess113
debugfs exerciser — a green board CANNOT close it (sess111 measured the
reconcile arm entered 0 times on all 32 nodes).
