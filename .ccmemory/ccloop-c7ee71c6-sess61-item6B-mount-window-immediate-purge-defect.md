---
name: ccloop-c7ee71c6-sess61-item6B-mount-window-immediate-purge-defect
description: sess61: GPT item 6B is a REAL SHIPPED CORRECTNESS DEFECT, line-proven — a peer death during any mount ran the legacy immediate purge (grants + HB sec…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, step4a, item6B, D2, defect, in-progress]
---

# sess61 — item 6B is a real defect, not just an availability gap

Build **0.11.405**, srcversion `B0403C96FF608243416F692`, compiles clean.
**STILL DO NOT BOARD** — 6B is half-landed, items 3, 4, 6C untouched.

## The defect, line-proven (stronger than GPT's framing)

GPT's 6B said: a peer healthy at mount step 6.5 can freeze during the 62 s
confirm window, its grants are not in `mount_stale_mask`, and they can block
`xfs_log_mount_finish`.  That is the *availability* half.  Reading the code
found the **correctness** half, which is far worse:

- `mxfs_v5_dlm_init` starts the disklock heartbeat **and wires
  `v5_lease_expire_cb`** at `dlm/v5_mount.c:2467-2471` — inside `fill_super`,
  **before** `xfs_mountfs`.
- `mxfs_dlm_cache_init` — which registers `dead_node_notify_fn`, the
  slice-replay hook — runs at `pal/linux/xfs_super.c:3080`, **after**
  `xfs_mountfs(mp)` at :3074.
- Old `v5_lease_expire_cb` gated the D2 deferred-purge path on
  `ctx->dead_node_notify_fn` being non-NULL and otherwise fell through to
  the **legacy immediate purge**: `mxfs_dlm_caw_purge_node` (clears the CAW
  authority manifest) + `mxfs_disklock_purge_node` (clears the lock records
  **and zeroes the dead node's heartbeat sector**, `dlm/disklock.c:1290-1307`).

A zeroed HB sector **is** the cluster-wide "slice replayed" broadcast — every
peer's monitor then fires `v5_recovered_cb` and runs its deferred local purge.
So any peer death inside the whole mount window (log recovery + the 62 s
barrier + `xfs_log_mount_finish`) published "recovery complete" for a slice
**nobody replayed**, and destroyed the manifest the foreign-replay gate reads.
That is the sess9 D2 torn-view defect restored (ifree destaged, dirent-remove
abandoned → durable dangling dirent), and it is reachable on the 32-node rig
every time a node reboots while another mounts.

## What landed in 0.11.405 (partial)

`dlm/v5_mount.c` only:

1. New ctx state: `mphase_lock` (created unconditionally right after the
   ctx alloc — before the heartbeat can fire, and on **both** transports;
   destroyed in `mxfs_v5_dlm_shutdown` **after** `disklock_stop_heartbeat`/
   `destroy`, i.e. just before `mxfs_pal_free(ctx)`), `mphase_dead_mask`,
   `mphase_dead_node[]`.
2. `v5_start_slice_recovery` split: new `v5_dispatch_slice_recovery` is the
   elect + notify + re-election-sweep half; the wrapper keeps the
   already-pending guard + `mark_recovery_pending` and then calls it.
3. New `v5_defer_slice_recovery`: mark recovery pending durably, record
   slot+node under `mphase_lock`, log `P233-MPHASE-DEATH` once per slot.
   Purges **nothing**.
4. `v5_lease_expire_cb` re-gated on **`dead_slot >= 0`**, not on the hook:
   a heartbeat slot means a journal slice, and a journal slice may never be
   purged before replay regardless of who lacks a hook.  Hook present →
   `start`; absent → `defer`.  The legacy purge now runs only when the node
   owns **no** slot (pre-claim death / lease-only peer) — its dead
   `dead_slot >= 0 && dlm_caw` caw-purge line was removed.
5. `P233-MPHASE-UNDISPATCHED` at teardown if the mask is non-empty.

## Remaining work for 6B (NOT done)

- **Drain API**: `mxfs_v5_dlm_mount_take_late_deaths(ctx, &mask)` (lock,
  read, clear, return) exported in `dlm/v5_mount.h`.
- **Barrier folds late deaths in**: restructure `mxfs_dlm_mount_recovery_barrier`
  step (c) into bounded ROUNDS — each round replays `cohort ∪ drained-late`,
  accumulating into `replayed`; loop while the drain returns new bits (cap
  ~4 rounds).  Costs no extra confirm time: the monitor does the 62 s
  confirm in parallel.  **`mount_cohort_complete(replayed)` must stay a
  SINGLE call after ALL rounds** — purging round-1 manifests before
  round-2 slices are replayed is the sess50 cross-slice-evidence violation.
- **Settle dispatches the remainder**: in `mxfs_v5_dlm_mount_settle` (runs
  post-`xfs_mountfs`, after `cache_init` registered the hook), drain the
  mask and `v5_dispatch_slice_recovery` each slot that is still
  `recovery_is_pending`.  Do NOT route through `v5_start_slice_recovery` —
  its already-pending guard would return immediately and never dispatch.
- **Residual, honest**: a death detected after the barrier returns leaves
  frozen grants that can stall `xfs_log_mount_finish` to the CAW timeout →
  mount fails, retry's step 6.5 picks it up as stale.  Correct but slow;
  `P233-MPHASE-DEATH` names it.  GPT 6A option 3 (mount-time acquire drives
  recovery of a stale owner) is the only real fix and is unbuilt.
- **RULE 6 ledger entry** for the mount-window immediate purge — not yet
  written to `tests/criteria/OPEN_DEFECTS.json` (no helper script exists;
  325 KB file, edit the one entry).

## Then

Items 3 and 4 (publication staging + foreign shadow-AIL lifecycle; own-bit
purge before `xfs_log_mount_finish`), then 6C, then a RULE-5 consult on the
whole set BEFORE any rig cycle.  Nothing from sess57 onward has been
measured on the rig.
