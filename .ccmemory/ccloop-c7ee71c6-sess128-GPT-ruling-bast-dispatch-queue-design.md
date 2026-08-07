---
name: ccloop-c7ee71c6-sess128-GPT-ruling-bast-dispatch-queue-design
description: sess128 RULE-5 GPT ruling on the BAST-delivery fix + the code landed so far: a preallocated resource-keyed coalescing dispatch queue.
metadata:
  type: reference
tags: [mxfs, dlm, caw, bast, rule5, gpt-ruling, performance, sess128]
---

# sess128 — RULE-5 ruling on the sess127 BAST-delivery root, and the landing

Root (sess127, unchanged): `bast_recv_fn` is ONE thread doing a synchronous
shared-LUN SCSI read per packet inside its recvfrom loop; RcvbufErrors=8085 on
a 4 MB locked sk_rcvbuf => BAST hints AND the grant nudges sharing that socket
are silently dropped. See `ccloop-c7ee71c6-sess127-ROOT-bast-recv-thread-disk-read-headofline`.

## NEW CORROBORATION found this session (dlm_caw.h:117-125)

sess8 already diagnosed this and tuned around it instead of fixing it:

> "A flat 25ms cadence regressed cc@32 60->91s: **every hint fires bast_cb on
> all receivers (no dedup)**, and ~31 waiters x 40/s melted the cluster in
> callback processing."

Two facts fall out: (1) cc@32 has a real historical PASS baseline of **60 s**;
(2) `MXFS_CAW_BAST_RESEND_FAST_MS`/`_FAST_COUNT` are **defined but never
referenced** — dead constants. The live cadence is a flat 100 ms.

## GPT RULING (verbatim-condensed; full text in the sess128 transcript)

(A) is the correct primary fix, with four amendments:

1. **Route the DISK POLL through the same queue.** This was the biggest miss in
   my draft. `bast_poll_fn` also called `ctx->bast_cb` inline, so today the recv
   thread and the poll thread can run callbacks for the SAME resource
   concurrently — nothing serializes them. Per-resource serialization is
   therefore NEW, not a relaxation.
2. **1-2 workers, not a pool.** Two == exactly today's recv+poll callback
   concurrency, so it cannot widen the liveness class. More needs a callback
   lock-order audit first.
3. **Queue-based coalescing, NOT time-based.** A 5-10 ms debounce adds latency,
   needs timers/shutdown state, and buys nothing — queue residence already
   grows exactly when dispatchers are busy.
4. **Do NOT keep POLL_RELAX_MS=4000 on the "UDP is up" premise.** The interval
   is not the recovery bound: a 256-slot window per pass means a full rotation
   costs `ceil(held.count/256) * interval` — 32768 slots at 4000 ms is ~512 s.

Hazards called out and honoured in the code:
- Mode merge must be the **conservative lattice join**, not numeric max — the
  modes are a partial order (CW and PR are incomparable). max(CW,PR)=PR, but
  PR's conflict set {CW,PW,EX} does not cover CW's {PR,PW,EX}. Correct join is
  PW. EX is a fixed point, which preserves `i_dlm_dir_want_ex`.
- Direct-mapped table is WRONG (collisions become artificial drops) — use
  preallocated pool + free list + hash chains + separate FIFO ready queue.
- Never hold the queue lock across `bast_cb`. Linearize submit and completion
  under the SAME lock or a hint is lost in the completion race.
- Re-arm requeues at the **TAIL**, not head (one hot resource must not starve
  the rest).
- Teardown order: stop+join PRODUCERS (recv, poll) first, then broadcast and
  join workers, then free. A detached worker that returns into a freed ctx is a
  UAF; `caw_join_bounded` already encodes this contract.
- **DEFER** the in-memory held-list prefilter (my option C): absence from
  non-authoritative memory is not proof of absence on disk (`held_overflow`,
  stale `slot_hints`, slot reuse, eviction/orphan paths). Rule: memory may
  establish a POSITIVE reason to process a BAST, never a negative one to drop it.
- **DEFER** the `mxfs_caw_orphan_forensic` offload (5.1% of release-side wall) —
  separate change, separate measurement.
- Sender-side aggregation is complementary, NOT a substitute; own cycle.

## LANDED SO FAR (0.11.452 tree, NOT yet built or deployed)

`dlm/dlm_caw.h`
- Block comment (the whole rationale) + `MXFS_CAW_BASTQ_ENTRIES 2048`,
  `_BUCKETS 2048`, `MXFS_CAW_BAST_WORKERS 2`, `_WAIT_MS 200`,
  `MXFS_CAW_BASTQ_FASTPOLL_MS 2000`.
- `enum mxfs_caw_bq_state {FREE,QUEUED,RUNNING}`, `struct mxfs_caw_bq_ent`.
- ctx `.bq` sub-struct (pool/hash/freelist/head/tail/lock/cond + depth,
  hiwater, running_n, submitted, merged, rearmed, dispatched, overflow,
  inline_cb, fastpoll_until_ms) and `bast_disp_thread[MXFS_CAW_BAST_WORKERS]`.

`dlm/dlm_caw.c` (inserted immediately before `bast_poll_fn`)
- `caw_bast_mode_join()` — searches the 6x6 `lock_compat` lattice for the
  minimum-conflict mode whose conflict set covers both inputs.
- `caw_bastq_init()` / `caw_bastq_free()` — preallocated; init failure is
  NON-fatal (submit falls back to an inline callback = pre-sess128 behaviour).
- `caw_bastq_enqueue_locked` / `_lookup_locked` / `_unhash_locked`.
- `caw_bast_submit()` — the single producer entry point.
- `caw_bast_disp_fn()` — the dispatcher.
- `bast_recv_fn` and `bast_poll_fn` both now call `caw_bast_submit()` instead
  of `ctx->bast_cb`.
- Poll relax gate honours `bq.fastpoll_until_ms` after an overflow.
- New probe `P264-BASTQ-FULL` (always-on, ratelimited).

## STILL TO DO (next session starts here)

1. **Wire lifecycle** — none of this runs yet:
   - `caw_bastq_init(ctx)` in `mxfs_dlm_caw_create` (near the `held.slots` /
     `mem_locks` allocs, ~dlm_caw.c:10867).
   - `caw_bastq_free(ctx)` in `caw_create_unwind` AND `mxfs_dlm_caw_destroy`.
   - Create the `MXFS_CAW_BAST_WORKERS` dispatchers in `mxfs_dlm_caw_start`
     **before** the poll thread (~dlm_caw.c:11052) so submissions are consumed.
   - Join them in stop PHASE 3 **after** `caw_join_bounded(bast_recv)` and
     `(bast_poll)` (~dlm_caw.c:11498) — producers first, then workers, then free.
     Also `mxfs_pal_cond_broadcast(ctx->bq.cond)` when `running` is cleared.
   - Unwind the dispatchers on a failed start like the poll thread does.
2. **Counters probe** — dump `bq.*` (submitted/merged/rearmed/dispatched/
   overflow/hiwater) somewhere harvestable; without it there is no way to prove
   the coalescing ratio.
3. Rev VERSION (0.11.453), `make modules`, deploy, then the measurement.
4. **PASS bar** (unchanged): `RcvbufErrors` delta across a run == 0;
   ino-128 mean grant wait 3533 ms -> <50 ms; releases/run far above 145;
   `caw_wait_for_grant` share 26% -> noise; **crash_consistency completes
   inside its 90 s budget on a VIRGIN fs** (`./run.sh 32 caw prep_cluster`
   then `./run.sh 32 caw crash_consistency`; recipe reproduces 3/3).

## Rig state at handoff

Fleet is on the tree build: srcversion `A1C4A05CB6356F02B8625F6` = 0.11.452,
confirmed on test1 via `/sys/module/mxfs/srcversion`. Nothing deployed yet from
this session's edits.
