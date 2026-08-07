---
name: ccloop-c7ee71c6-sess50-step4-code-facts-purge-ordering
description: sess50 line-verified code facts for foreign-replay step 4: the three purge sites, mount vs recovery ordering, and why deferring the own-slot purge se…
metadata:
  type: reference
tags: [foreign-replay, D-FOREIGN-REPLAY, step4, purge-ordering, dlm_caw, v5_mount, code-facts]
---

# Step-4 code facts — the three CAW-authority purge sites (sess50)

Ruling that consumes these: [[ccloop-c7ee71c6-sess50-GPT-ruling-step4-ordering-and-two-new-defects]].
Campaign: [[compiled-foreign-replay-authority-tokens]]. All line-verified against
0.11.398.

## Where authority can be destroyed — exactly three sites

1. **`mxfs_v5_dlm_recovery_complete` (`v5_mount.c:1274`)** — live foreign replay.
   **ORDER IS ALREADY CORRECT.** `mxfs_dlm_foreign_replay_work_fn`
   (`xfs_mxfs_dlm.c:41796`) does peer_joined_flush → `mxfs_xlog_recover_foreign_slice`
   → peer_joined_flush → `recovery_complete`. `mxfs_dlm_peer_joined_flush`
   (`xfs_mxfs_dlm.c:41042`) = `xfs_log_force(SYNC)` + `xfs_ail_push_all_sync` +
   `mxfs_blkdev_flush_epoch`, ×2 with a 20 ms gap, then invalidates every pag's
   cached AG-meta bufs. So replay output IS durable before the purge.
   Inside recovery_complete: CAW purge → lease unregister → in-memory dlm purge →
   clear pending → `mxfs_disklock_purge_node` (zeroes the dead HB slot = the
   cluster-wide done broadcast). **The gap between the CAW purge and the zeroing is
   the crash window GPT says forces a durable REPLAYED state.**

2. **Mount own-slot purge (`v5_mount.c:1765-1773`, mask `1<<node_slot`)** —
   CLAIM B. Runs inside `mxfs_v5_dlm_init`, called from `xfs_super.c:3038`
   **BEFORE** `xfs_mountfs` (`:3074`) → `xfs_log_mount` → `xlog_recover`
   (`xfs_log.c:688`). Everything between it and recovery — CAW start, heartbeat
   start, version join gate, cross-instance stale purge (10 s), discovery,
   membership settle (up to 20 s) — runs with our previous incarnation's AGs
   de-quarantined while our slice is still dirty and PASS-1 replay is UNGATED.

3. **Mount cross-instance stale purge (`v5_mount.c:1831-1845`)** — CLAIM C.
   `mxfs_disklock_get_stale_slot_mask` (`disklock.c:2484`) snapshots every
   `MXFS_DISKLOCK_FLAG_ACTIVE` slot, waits/polls up to 5×HB interval, and marks
   any slot whose `timestamp_ms` did not advance. **It excludes only `skip_slot`
   (our own).** A victim whose foreign replay is IN FLIGHT on another survivor is
   ACTIVE-with-frozen-timestamp → declared stale → its CAW authority purged by the
   mounting node. That breaks the shipped sess9 D2 invariant ("grants held by the
   dead node stay frozen until its slice is replayed") independently of tokens —
   it is the readmission of the exact bug D2 fixed (PROVEN drc@16 r13: durable
   dangling dirent).

## Why the CLAIM B fix cannot be a bare "move the purge later"

`mxfs_dlm_caw_acquire` (`dlm_caw.c:3770`): `our_mode = node_held_mode(cur_slot,
ctx->node_bit)`.
- `our_mode == mode` → fast-path SUCCESS (guarded by `compatible_excluding_self`
  at `:3794`; if a peer holds an incompatible mode our bit is provably stale, gets
  CAS-cleared, and the acquire retries normally — P37-INSTR).
- `our_mode != mode` (stale EX bit, we now want PR — or the reverse) → falls
  through to the normal wait. `is_compatible` sees OUR OWN bit and says no.
  `v5_caw_holders_alive` (`v5_mount.c:912`) then reports the holder ALIVE, because
  the holder slot is our own reclaimed slot and we are heartbeating — so the wait
  is liveness-EXTENDED to `MXFS_CAW_WAIT_HARDCAP_MS` (8 min) before -ETIMEDOUT.
  **We wait on ourselves for 8 minutes, then fail the mount.**

So the previous incarnation's bits must be conflict-blocking against PEERS but
transparent to US — GPT's `RECOVERING_OLD_INCARNATION` / recovery-only
self-conflict bypass. Confirmed necessary, not optional.

Second hazard on the same path: the `our_mode == mode` fast path would ADOPT a
stale EX bit as a live grant, skipping the fresh-acquire FUA read. At mount the
buffer cache is empty so no stale content is served, but the bypass must not
extend that adoption past recovery.

## Structure facts

`struct mxfs_caw_lock_slot` (`dlm_caw.h:150`, exactly 512 B): holders are five
`uint64_t` slot bitmaps (`holders_ex/pw/pr/cw/cr`). `ex_grant_epoch` is a SINGLE
field, not per-holder — sound because EX/PW are mutually exclusive, so at most one
exclusive holder exists. Its in-tree comment already states the step-4 premise:
"at fencing, the frozen slot (dead node's EX bit + this epoch) IS the held-at-death
manifest."

`recovery_pending[]` / `pending_node[]` (`disklock.h:350`) are **in-memory
per-node arrays**, not on disk — acceptable as a scheduling hint only (GPT A(iii)),
so the durable REPLAYED state cannot be built on them.

## Natural landing sites

- Post-recovery hook for both mount purges: `xfs_super.c:3078` "Post-mountfs DLM
  setup" — after `xfs_mountfs` returns, i.e. after `xlog_recover` AND
  `xfs_log_mount_finish` (intent processing, `xfs_mount.c:1175`).
- Durable REPLAYED state: the victim's own disklock HB record is already 512 B,
  CRC-covered, and carries `epoch` (= node-instance/boot epoch = the ruling's
  `owner_boot_epoch`). A new flag/state value there is the cheapest durable
  binding. **Audit every `hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE` comparison
  first** — e.g. `disklock.c:2531` filters the stale scan on exact equality, so a
  composite flag value would silently change liveness/stale semantics.
- Stale dirty slices found at mount can be routed into the EXISTING
  `mxfs_dlm_foreign_replay_work_fn` machinery, which already implements the
  correct replay→flush→purge order; post-mountfs is where `mp->m_log` exists.
