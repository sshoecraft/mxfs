# dlm_caw — Compare-and-Write DLM

## Purpose

Disk-based distributed lock manager using SCSI Compare-and-Write (CAW) for
atomic lock state transitions. Replaces the TCP-based DLM — the shared block
device is the lock master, eliminating all TCP peer-to-peer connections for
lock coordination. This is the primary/default transport (`caw`/`cawp`/`cawd`
deployment conditions); TCP DLM (dlm.c) remains available and is validated
to 32 nodes but hits a single-lock-master-per-resource bottleneck above ~16
nodes (see dlm.md).

As of the 2026-07-20 criteria-met sweep, this transport is validated
1-32 nodes across all three CAW deployment conditions (`cawp` passthrough,
`cawd` direct, `caw`) plus TCP (`tcp`) on one consistent build
(0.11.39) — see `state.md` and `CHANGELOG.md` for the validation history.

## On-Disk Layout

Lock slots reside in the disklock region, starting at `base_offset +
MXFS_DISKLOCK_HB_SIZE` (32 KB after the heartbeat area). Each slot is exactly
512 bytes (one sector) for atomic CAW operations. Total: 65536 slots.

### Lock Slot Structure (512 bytes)

- `magic` (u32) — `MXFS_CAW_MAGIC` (0x4D584357)
- `generation` (u32) — ABA counter, incremented on every modification
- `resource` (32 bytes) — the mxfs_resource_id being locked
- `holders_ex/pw/pr/cw/cr` (5 x u64) — per-mode bitmaps (bit N = node N)
- `waiters` (u64) — bitmap of nodes waiting for a conflicting lock
- `granted_mode` (u8) — highest mode currently held
- `waiter_mode` (u8) — highest mode any waiter needs
- `ex_grant_streak` (u32) — count of consecutive EX/PW grants since the last
  shared-class grant, maintained inside the grant CAS (was `pad2`). See
  "PR anti-starvation" below.
- `last_modified_ms` (u64) — timestamp of last modification
- `yield_to` (u64) — bitmap of nodes with priority for next acquire
- `yield_set_ms` (u64) — timestamp when yield_to was set
- `waiters_ex` (u64) — bitmap of nodes waiting for an EXCLUSIVE-class mode
  (EX or PW); subset of `waiters`. Lets `recompute_waiter_mode` downgrade
  `waiter_mode` from EX back to PR once the last exclusive waiter leaves
  while shared waiters remain (without it, `waiter_mode` sticks at EX and
  starves fresh PR readers forever)
- `dir_epoch` (u32) — cross-node EX-handoff epoch, the CAW analog of the TCP
  master's per-resource `dir_epoch`. Bumped by the acquirer inside the grant
  CAS whenever it takes an EX-class mode and `last_ex_slot` names a
  different node; every grant reports the observed value to the XFS layer,
  which reloads the directory when its last-seen epoch no longer matches
- `last_ex_slot` (u8) — node_slot of the most recent EX-class holder;
  `MXFS_CAW_EX_SLOT_NONE` until the first EX grant on this slot
- `dir_block0_fsb` / `dir_block0_gen` (u64 / u32) — canonical directory
  logical-block0 record, write-once per directory incarnation (`di_gen`).
  The first node to materialize block0 for a shortform→block conversion
  publishes `{fsb,gen}` here (CAS write-once: first publisher wins); every
  later node about to convert the *same* incarnation's shortform directory
  checks this first and adopts the canonical block instead of allocating a
  second one — closes a directory double-allocation race that `dir_epoch`
  alone cannot (epoch is a relative/timing-sensitive check a simultaneous
  first acquirer can race past; this is an absolute existence check)
- `reserved` (364 bytes) — padding to 512

## Slot Addressing

FNV-1a hash of the `mxfs_resource_id` bytes determines the base slot
(`resource_hash_raw()`, lifted to `dlm_shared.c` — see dlm.md's "Shared
code note"; `fnv1a_hash` in dlm_caw.c is now an alias-by-rename of the
same function). Linear probing resolves collisions. Empty slots are
detected by `magic != MXFS_CAW_MAGIC`. The first gap terminates the probe.

A per-resource slot hint cache (`slot_hints[]`, `MXFS_CAW_SLOTHINT_SIZE`
entries) short-circuits the walk on a content-validated hit against the
last-known slot index; a miss falls back to the full probe below.

**Probe-chain span reads (ccloop 72513a13 sess3):** `find_slot_skip()`'s
probe-chain walk used to issue one synchronous 512B FUA `READ(16)` per
candidate slot — kprobe-measured at 9.2 FUA reads per file CREATE under
32-node contention (long chains from tombstone churn). It now reads the
chain in `MXFS_CAW_PROBE_SPAN`-slot (16) spans via `read_slot_span()` (one
larger `READ(16)` covering up to 16 contiguous slots), falling back to the
old per-slot `read_slot()` for the corrupt-looking-slot repair path and on
any span I/O error. Walk order and the claim-race protocol (CAW against
live content, post-claim `skip_idx` re-walk) are unchanged.

### Lock

1. `find_slot()` — hash + linear probe (span-read, see above) to locate an
   existing slot or the first empty one
2. If not found: CAW an empty slot with the new resource and our holder bit
3. If found and compatible: CAW to add our bit to the appropriate holder bitmap
4. If found and incompatible:
   - `NOQUEUE`/`TRYLOCK`: return immediately
   - Otherwise: CAW to set our waiter bit, send UDP BAST hint, poll disk
     (see "Wait/poll loop" and "Grant Nudge" below)
5. On MISCOMPARE (`-EAGAIN`): retry from step 1 (up to 100 retries)

A successful grant/claim that leaves other waiter bits set in the slot
fires a UDP grant nudge (see "Grant Nudge" below) so any queued waiters
re-check immediately instead of on their next poll tick.

### Wait/poll loop (`caw_wait_for_grant`)

- **Base timeout**: `MXFS_CAW_WAIT_TIMEOUT_MS` = 120s, as before.
- **Liveness-extended ceiling (ccloop 72513a13 sess2)**: past the base
  timeout, the wait keeps extending *only* while every blocking holder bit
  in the slot is provably alive per an externally-wired liveness oracle
  (`ctx->holders_alive_fn`, set via `mxfs_dlm_caw_set_holders_alive_fn()` —
  wired from the v5 mount path over disklock heartbeat state), up to a
  hard cap `MXFS_CAW_WAIT_HARDCAP_MS` = 480s (8 min). Rationale: dead
  holders are already detected and purged by disklock lease expiry (their
  slot bits get cleared and the waiter promotes on its own), so the base
  120s timeout's only real job is dead-holder detection — but under
  32-node fio saturation, a *live* holder's hold time (dio-completion
  convoys feeding AG/extent-conversion chains) can legitimately cross
  120s. Timing that out as `-ETIMEDOUT` surfaced into userspace I/O errors
  and, worse, into `xfs_mxfs_dlm.c`'s force-shutdown path — one wedged-but-
  live holder cascaded into 31 peer shutdowns on the 0.11.8 board. Past
  the hardcap (or once no holder is provably alive, or the oracle is
  unwired/NULL), the wait still times out normally — a live-but-wedged
  holder (the P113 class) surfaces as a timeout instead of hanging
  forever. Each extension episode logs `P-WAIT-EXTEND`.
- **Fair-handoff ticket honor**: see "Yield-on-Contention Fairness" below.
- **Nudge-aware sleep**: each poll iteration sleeps on the grant-nudge
  condvar instead of a plain timed sleep (see "Grant Nudge" below), so a
  releaser's multicast wakes the waiter immediately in the common case;
  the poll interval remains the lossless backstop for a lost packet.
- **P138-WAIT diagnostic** (INODE-type waits >5ms): capped at 4000 lines
  (was unconditionally ratelimited — storm runs were losing most lines),
  now also reports `ffw_ms` (grantable→claimed latency), `ytd` (fair-
  handoff ticket deferrals seen while otherwise grantable), `poll`
  (current poll interval), and `realms` (wall-clock time via
  `mxfs_pal_time_real_ms()`, for cross-node hop pairing against the
  releaser's own exit timestamp).

### Unlock

1. `find_slot()` to locate the resource
2. CAW to clear our bit from all holder bitmaps
3. If slot becomes empty (no holders, no waiters): zero the entire slot
4. Remove from local held list
5. If the slot had other waiter bits set, fire a UDP grant nudge (see
   "Grant Nudge" below)

**Unlock retry-to-deadline scope (ccloop 72513a13 sess6):** the wall-clock
unlock retry bound (`mxfs_caw_unlock_backoff`, see "Anti-storm knobs"
below) now also covers `MXFS_LTYPE_ICLUSTER` resources, not just
`MXFS_LTYPE_INODE`. Proven at 32/cawd: an ICLUSTER unlock kept the old
tight 100-retry cap, exhausted it against 32-node waiter-bit churn, and
the swallowed failure left a stale on-disk cluster EX bit that starved
all 32 nodes' PR acquires for 380s+ (the holder keeps heartbeating, so the
liveness-extended wait above just kept extending). Releasing later is
never a double-grant, so retry-to-deadline is exactly as safe for
ICLUSTER as it already was for INODE.

### Convert

Handles both upgrade and downgrade:
- Downgrade: always succeeds (reducing lock strength)
- Upgrade: checks compatibility excluding self; if blocked, registers as
  waiter and polls like a new lock request

## Yield-on-Contention Fairness

Prevents lock starvation under high contention (e.g. 8 nodes racing for the
same directory lock). Without this, the same fast nodes keep winning the CAW
race and slower nodes get starved (0/500 files).

### Mechanism

When a holder releases a lock and waiters are present, the unlock path sets
`yield_to = waiters` in the slot. This gives the waiting nodes priority:

1. **Non-priority node tries to acquire**: If `yield_to` has bits set and the
   acquirer is NOT in `yield_to`, the acquirer backs off (sleeps 3-13ms
   jittered by node_id) and retries. This prevents the releasing node from
   immediately reacquiring.

2. **Priority node acquires**: If the acquirer IS in `yield_to`, it clears
   its bit and proceeds normally.

3. **Stale yield_to timeout**: If `yield_to` has been set for >5 seconds
   (checked via `yield_set_ms`), any node can clear it via CAW and acquire.
   Prevents deadlock if a yielded-to node dies before acquiring.

4. **Node purge/release_all**: Dead node bits are cleared from `yield_to`
   during `purge_node()` and `release_all()`.

### `caw_fair_handoff` — default flipped ON (ccloop 72513a13 sess6)

The round-robin ticket mechanism above is gated by the `caw_fair_handoff`
module param, **default now 1** (was 0/off). A/B on a fresh 32-node
cluster: free-for-all (`fair_handoff=0`) left 16 of 32 nodes' creates
hung >90s — victim-node starvation is fatal at this scale, not just slow.
With `fair_handoff=1` all 32 completed in ≤2.5s (p50 942ms). An earlier
"fair=1 is catastrophic" reading (p90=46s, recorded pre-0.11.20) turned
out to be a poisoned-cluster artifact: killed prior runs had leaked stale
`yield_to` waiter bits, and the 5s stale-ticket clear (`yield_set_ms`
timeout) dominated the measurement — on clean state the rotation is
sound. See `state.md` SESS6 PART-3 for the full A/B ledger, including the
write-phase regressions this surfaced (ticket-linger tax on PR acquires
after write phases) that motivated the adaptive MHT floor work in
`xfs/xfs_mxfs_dlm.c` (out of this doc's scope).

### PR anti-starvation: EX grant streak (`ex_grant_streak`)

Independent of the yield-ticket mechanism above, `ex_grant_streak` (on-disk
field, see "On-Disk Layout") counts consecutive EX/PW grants since the last
shared-class (PR/CR/CW) grant, maintained inside the same CAS as the grant
itself. Once the streak reaches `MXFS_CAW_EX_STREAK_YIELD` (3), the
fair-handoff release chooser yields one turn to the *entire* shared waiter
class instead of the next EX-class ticket holder. Proven necessary: without
it, a verify-phase readdir's PR acquire starved 240s behind 31 creators
round-robining a directory's EX lock via the yield-ticket mechanism alone
(yield_to only rotates within the EX-waiter set), ending in an rc=-110
shutdown.

## BAST (Blocking AST) Notifications

Two complementary paths (port/address now sourced from the central registry
`include/mxfs/mxfs_ports.h` — `MXFS_CAW_BAST_PORT` = `MXFS_PORT_CAW_BAST`,
numerically unchanged at 7602):

1. **UDP multicast** — When a waiter registers, it sends a BAST hint packet
   to `239.66.83.1:7602` (`MXFS_BAST_MAGIC`). Holders receiving the hint
   fire their BAST callback to flush/release. Fast but unreliable (UDP).
   Resend cadence while blocked: flat `MXFS_CAW_BAST_RESEND_MS` = 100ms.
   (The header also defines `MXFS_CAW_BAST_RESEND_FAST_MS`/`_FAST_COUNT`
   for a burst-first-4-resends-at-25ms scheme — **not currently wired into
   the resend loop**: sess8 A/B'd both a flat 25ms cadence and a 4×25ms
   leading burst and both regressed cc@32 (60s → 84-91s), because every
   resend fires `bast_cb` on all receivers with no dedup and the flood
   drowns the grant-nudge wakeups the handoff depends on. The constants
   are left in the header as a documented negative result / future lever.)

2. **Poll thread** (`bast_poll_fn`) — Scans all locally-held lock slots
   from disk. If any slot has waiters with an incompatible mode, fires the
   BAST callback. Adaptive interval, three tiers (ccloop 72513a13 sess3,
   revised from the doc's earlier 5ms/200ms figures):
   - `MXFS_CAW_BAST_POLL_FAST_MS` = 100ms — under contention
   - `MXFS_CAW_BAST_POLL_RELAX_MS` = 4000ms (was 1000ms) — idle, UDP BAST
     path operational. Waiters already re-send hints every 100ms while
     blocked, so this disk poll is packet-loss insurance only; at 1000ms
     it was the #1 idle/rm-phase disk-read source (kprobe-counted ~13k
     reads per 8-node dir_reuse round at the old value)
   - `MXFS_CAW_BAST_POLL_MS` = 200ms — idle, UDP socket failed to set up
     (disk poll is the only BAST channel in that case)
   Sleeps via condvar timed-wait so it wakes instantly on shutdown signal.

### Grant Nudge (ccloop 72513a13 sess3) — the reverse of the BAST hint

A releasing/handing-off node that just committed a slot CAW (grant, unlock,
or self-promote) and observes other waiter bits still set in the new slot
image multicasts `MXFS_GRANT_MAGIC` (same UDP wire struct as the BAST hint,
distinguished by magic) to `239.66.83.1:7602`. Any node with a local waiter
blocked in `caw_wait_for_grant`'s poll loop wakes immediately instead of
riding out its poll interval (kprobe-proven: 4.6s of a 6.0s 8-node create
phase was waiters sleeping in acquire polls before this existed).

Mechanics: `ctx->nudge_lock`/`nudge_cond`/`nudge_seq` (allocated in
`mxfs_dlm_caw_create()`, non-fatal on allocation failure — falls back to
plain `sleep_ms`). A waiter snapshots `nudge_seq` (`caw_nudge_prepare()`)
*before* its slot read, then sleeps on the condvar via `caw_nudge_wait()`
for up to the current poll interval; the receive thread (`bast_recv_fn`)
bumps `nudge_seq` and broadcasts on every received `MXFS_GRANT_MAGIC`
packet. Snapshotting the sequence before the read closes the lost-wakeup
window (a nudge racing in between the read and the prepare call is missed
and costs at most one poll interval — bounded by the disk-poll backstop).
Coarse by design: any nudge wakes *all* local waiters, who each re-check
their own slot with one read.

## Node Purge

`mxfs_dlm_caw_purge_node()` scans all 65536 slots. For each active slot where
the dead node has bits set in any holder or waiter bitmap, clears them via CAW.
Yields periodically (every 256 slots) to prevent soft lockups.

`mxfs_dlm_caw_purge_dead_nodes()` takes a 64-bit dead_mask and purges all dead
slots in a single pass through the 65536 lock slots. Used at mount time to
clear stale holder bits from crashed nodes without waiting for heartbeat
detection (62s) or lock wait timeout (120s).

## Single-Node Bypass (v0.9.28)

When no peers exist, all CAW disk I/O for locks is pure waste. The single-node
bypass eliminates it entirely:

### In-Memory Fast Path

When `ctx->single_node` is true (set at mount, cleared on peer discovery):

- **`mxfs_dlm_caw_lock()`** — Grants immediately in-memory. Tracks the
  (resource, mode) in `ctx->mem_locks[]` for later flush-to-disk.
- **`mxfs_dlm_caw_unlock()`** — Removes from in-memory tracking. No disk I/O.
- **`mxfs_dlm_caw_convert()`** — Updates in-memory mode. No disk I/O.
- **`bast_poll_fn()`** — Skips the disk-polling iteration entirely (just sleeps
  and loops). No peers means no waiters can exist on disk.

### Transition: Single-Node to Multi-Node

When `discovery_peer_cb()` fires (peer announces via multicast), mount.c calls
`mxfs_dlm_caw_set_single_node(ctx, false)`. This triggers
`mxfs_dlm_caw_flush_held_to_disk()`, which:

1. Snapshots all in-memory held locks under `mem_lock_mutex`
2. For each lock, claims a disk slot via find_slot + CAW (same as normal lock)
3. Clears the in-memory list after all locks are flushed
4. After this, all subsequent lock ops go through the normal disk path

The BAST poll thread automatically resumes disk-scanning on the next iteration
since `single_node` is now false.

### Safety

This optimization is zero-risk in the single→multi direction because:
- The flush happens BEFORE the flag is cleared, so there is no window where
  a peer could miss a held lock
- `discovery_peer_cb` fires before any peer attempts to acquire locks (the
  peer must complete its own mount sequence first)
- If flush fails (I/O error), the error is logged but multi-node mode is still
  entered — locks acquired after the transition use normal disk I/O

## Thread Model

- **bast_poll_fn** — Periodic held-slot scanner, fires BAST callbacks.
  Skips disk polling when `ctx->single_node` is true.
- **bast_recv_fn** — UDP multicast receiver for BAST hint packets *and*
  grant-nudge packets (`MXFS_GRANT_MAGIC`, see "Grant Nudge" above) —
  distinguished by wire magic on the same socket.

Both threads check `ctx->running` and exit cleanly on stop. The poll thread
uses a condvar timed-wait instead of plain sleep so `mxfs_dlm_caw_stop()` can
wake it instantly by signaling the condvar.

## Module Parameters (tuning / anti-storm knobs)

All under `mxfs.` (kernel module params, `sysfs`-writable at runtime,
`0644`):

| Param | Default | Purpose |
|---|---|---|
| `caw_fair_handoff` | **1** (flipped from 0, ccloop 72513a13 sess6) | Round-robin inode-EX handoff via `yield_to`. See "Yield-on-Contention Fairness". |
| `caw_unlock_backoff` | **1** (flipped from 0, ccloop 72513a13 sess5) | Wall-clock-bounded (not retry-count-bounded) jittered retry on inode/ICLUSTER unlock CAS miscompare — an unlock must always complete; a failed unlock wedges the cluster. |
| `caw_inode_fastpoll` | 1 (v0.10.39) | Fixed 2ms poll (no exponential backoff) for the first 64ms of an inode lock wait — a BAST-driven handoff completes in ~10-25ms, so the old 1/2/4/8/16/25ms backoff parked the waiter up to 25ms after the slot was already free. |
| `caw_epoch_free_reset` | 1 (v0.10.39, dlm_scaling fix) | Clears a freed inode's CAW slot `dir_epoch`/`last_ex_slot` at free time (piggybacked on the unlock's tombstone CAS, zero extra I/O) so a reused inode number doesn't inherit a stale cross-node-handoff signal from its predecessor incarnation. |
| `caw_gen_verify` | 0 | Caller-level CAW generation verify after every `caw_slot()` success (diagnostic; off by default). |

## Compatibility Matrix

Reuses the exact same 6-mode matrix as the TCP DLM (dlm.c) — as of the
NET2 §11 step-3 lift (2026-07-17), both live in `dlm_shared.c`/`.h` as one
shared table rather than two copies:

```
       NL  CR  CW  PR  PW  EX
  NL    Y   Y   Y   Y   Y   Y
  CR    Y   Y   Y   Y   Y   N
  CW    Y   Y   Y   N   N   N
  PR    Y   Y   N   Y   N   N
  PW    Y   Y   N   N   N   N
  EX    Y   N   N   N   N   N
```

## Additional Query/Recovery APIs

Beyond the core lock/unlock/convert surface, dlm_caw.c exposes:

- `mxfs_dlm_caw_granted_mode(ctx, resource)` (ccloop cc87fed3 sess3) — real
  per-node granted mode (`MXFS_LOCK_*`, NL if not held), unlike
  `mxfs_dlm_caw_held()` which collapses to a boolean. Needed because a
  caller that upgrades its in-core mode to whatever it reads back must not
  treat a real PR-only hold as EX. Mirrors the TCP-side
  `mxfs_dlm_granted_mode()` contract so callers can treat both transports
  uniformly.
- `mxfs_dlm_caw_self_held_scan(ctx, resource, nslots_out, hex_or_out)` /
  `mxfs_dlm_caw_force_release_self(ctx, resource)` (ccloop a864 sess3) —
  duplicate-immune orphan-bit recovery. The scan walks the *entire* probe
  chain (not just the hinted slot) and ORs `holders_ex` across every live
  slot matching `resource`, catching an orphaned EX bit that the hinted
  `mxfs_dlm_caw_held()` can miss when a claim-race left the resource in
  more than one live slot. `force_release_self()` unconditionally CAS-clears
  the local node's bit from every holder/waiter/yield bitmap across the
  whole chain — recovery for an orphaned holder bit that the normal
  hinted/seq-gated unlock left set (proven live: a bit cleanly findable by
  the scan but never cleared by the normal path wedged a 32-node
  dir_reuse run). Caller must already hold the local DEMOTING claim
  (in-core mode==NL) so no fresh grant is clobbered.
- `mxfs_dlm_caw_grant_dir_block0()` / `mxfs_dlm_caw_set_dir_block0()`
  (query/publish for the `dir_block0_fsb`/`dir_block0_gen` on-disk field —
  see "On-Disk Layout").
- `mxfs_dlm_caw_orphan_clock_get()`/`_set()` — resource-keyed (not
  inode-keyed) wall-clock orphan/BAST-starve trackers, backed by their own
  table (`ctx->orphan_clock[]`, `MXFS_CAW_ORPHANCLOCK_SIZE` = 4096 entries)
  with a dedicated spinlock (never sleeps — callers run with an
  `xfs_inode` spinlock held from `xfs_mxfs_dlm.c`'s BAST processing).
  Resource-keyed because the equivalent per-inode fields
  (`i_dlm_orphan_since_ns`/`i_dlm_bast_starve_since_ns` in
  `xfs/xfs_inode.h`) get silently reset whenever the in-core VFS inode is
  evicted and reinstantiated, which a hot create/unlink storm does faster
  than the escape thresholds can accumulate continuous observation.
- `mxfs_dlm_caw_set_holders_alive_fn()` — wires the liveness oracle used by
  the wait-timeout extension (see "Wait/poll loop" above).

The grant-meta cache (`ctx->grant_meta[]`) that backs `dir_epoch`,
`dir_block0_fsb/gen`, and the grant-episode sequence was widened from
`MXFS_CAW_GRANTMETA_SIZE` = 4096 to 32768 direct-mapped entries: at 4096,
a 32-node run's ~200-resource working set hit birthday-certain hash
collisions, and a colliding claim used to wipe the victim entry's
`releasing` mark and `grant_seq` (the v0.6.2 unlock-vs-regrant race
protections) — 339 anchor-less releases observed in one run. 32768
entries (~1.5MB/mount) makes collisions rare; the no-wipe wait already
added in store/prebump/release_mark makes the residual ones harmless.

## Dependencies

- `dlm.h` — for `mxfs_dlm_bast_cb` typedef, lock mode constants
- `dlm_shared.h` — compatibility matrix, `resource_hash_raw()`/`fnv1a_hash`
  (renamed to the shared name), `is_compatible()`,
  `recompute_granted_mode()`, `caw_slot_holders_popcount_ok()` (all shared
  with dlm.c and the NET2 lock plane since 2026-07-17)
- `disklock.h` — for `MXFS_DISKLOCK_HB_SIZE`
- `discovery.h` — for `MXFS_DISCOVERY_MCAST` (multicast group address)
- `include/mxfs/mxfs_ports.h` — `MXFS_PORT_CAW_BAST` (port registry)
- `pal.h` — all platform operations (I/O, threading, networking, memory, time)

## History

- (uncommitted, ccloop 72513a13 sess2-6, on top of 0.11.x) **Wait-timeout
  liveness extension + grant-nudge + probe-span reads** — the largest
  behavioral batch since 0.10.120. Grounded directly in the current
  working-tree diff (`git diff HEAD -- dlm/dlm_caw.c`, `dlm/dlm_caw.h`):
  1. **sess2 — CAW lock-wait liveness extension.** Added
     `MXFS_CAW_WAIT_HARDCAP_MS` (480s) and `ctx->holders_alive_fn`
     (wired via new `mxfs_dlm_caw_set_holders_alive_fn()`, called from the
     v5 mount path over disklock heartbeat state). Past the existing 120s
     base timeout, `caw_wait_for_grant()` now keeps waiting *only* while
     every blocking holder bit is provably heartbeating, up to the hard
     cap. Root cause: dead holders are already purged by disklock lease
     expiry, so the base timeout's real job was already redundant for
     dead holders — but under 32-node fio saturation a *live* holder's
     hold time can legitimately exceed 120s (dio-completion convoys on
     ILOCK feeding AG/extent-conversion chains), and timing that out
     cascaded into `xfs_mxfs_dlm.c`'s force-shutdown path (one wedged
     live holder → 31 peer shutdowns on the 0.11.8 board). Each extension
     episode logs `P-WAIT-EXTEND`. See "Wait/poll loop" above.
  2. **sess3 — UDP GRANT NUDGE.** New `MXFS_GRANT_MAGIC` wire message
     (`caw_send_grant_mcast()`), `ctx->nudge_lock`/`nudge_cond`/`nudge_seq`,
     `caw_nudge_prepare()`/`caw_nudge_wait()`. A releaser/handoff that
     leaves other waiter bits set nudges them awake instead of leaving
     them to the poll interval; measured 4.6s of a 6.0s 8-node create
     phase was waiters asleep in acquire polls before this. `bast_recv_fn`
     now demuxes `MXFS_GRANT_MAGIC` alongside `MXFS_BAST_MAGIC` on the
     same socket. See "Grant Nudge" above.
  3. **sess3 — probe-chain span reads.** `find_slot_skip()` reads the
     probe chain in `MXFS_CAW_PROBE_SPAN` (16)-slot spans
     (`read_slot_span()`, new) instead of one FUA `READ(16)` per slot —
     kprobe-measured 9.2 FUA reads per file CREATE before the fix. Falls
     back to per-slot `read_slot()` on a corrupt-looking span slot or any
     span I/O error.
  4. **sess3 — P87 grant-persist readback sampling.** `caw_verify_grant_persisted()`
     now takes the resource and samples INODE-type EX/PW grants at 1/64
     instead of every grant (AG grants, which have free-space lost-update
     blast radius, stay at every-grant). This read-back was ~1 extra FUA
     read per created/unlinked file cluster-wide.
  5. **sess3 — P139-COLDCLAIM / P138-WAIT anatomy diagnostics.** New
     capped (not ratelimited, 4000-line cap) `pr_warn` diagnostics:
     `P138-WAIT` now reports `ffw_ms`/`ytd`/`poll`/`realms` (see "Wait/poll
     loop" above); new `P139-COLDCLAIM` fires when an INODE-type grant is
     claimed directly (not through `caw_wait_for_grant`) on a slot that
     had a yield ticket or queued EX waiters — i.e. the winner arrived
     *after* the release (a late-arrival hop), reporting whether the
     releaser's round-robin ticket had named this node.
  6. **sess6 — unlock retry-to-deadline scope widened to ICLUSTER.**
     `mxfs_caw_unlock_backoff`'s wall-clock retry bound
     (`MXFS_CAW_UNLOCK_DEADLINE_MS`) now also gates `MXFS_LTYPE_ICLUSTER`
     resources, not just `MXFS_LTYPE_INODE` — proven at 32/cawd (see
     "Unlock" above).
  7. **sess6 — `caw_fair_handoff` default flipped 0→1.** See
     "Yield-on-Contention Fairness" above for the A/B evidence.
  8. **`BAST_POLL_RELAX_MS` 1000→4000ms**, `caw_slot_holders_popcount_ok()`
     lift (see below), and `#include "dlm_shared.h"`.
- 2026-07-17 (NET2 §11 step 3, gate 3 GREEN, committed): **CAW-neutral
  shared-code lift.** `lock_compat`, `fnv1a_hash` (renamed
  `resource_hash_raw`, now byte-identical to dlm.c's copy — 17 call sites
  renamed), `holders_for_mode_const`, `is_compatible`,
  `recompute_granted_mode`, and the v0.3.83 EX/PW single-holder popcount
  check (extracted from `slot_appears_corrupt` as
  `caw_slot_holders_popcount_ok()`) all moved to the new
  `dlm_shared.c`/`dlm_shared.h`, shared with dlm.c and the NET2 lock plane.
  `mxfs_pal_popcount64` (both the kernel `hweight64()` wrapper and the
  user-mode manual-count variant) also moved there. Behavior-neutral,
  verified by `tests/net2/gate3_cawsanity.sh`. Changes: dlm_caw.c/h,
  dlm_shared.c/h (new).
- 2026-07-17 (0.10.120, committed 5968d6f "1-32 node CAW multipath ladder
  green; double-alloc root fix" — batch summary from `git diff c78d135
  5968d6f -- dlm/dlm_caw.c`, ~820 lines): several independent fixes landed
  in this build; the on-disk slot layout gained two field groups (see
  "On-Disk Layout"):
  1. **`ex_grant_streak` PR anti-starvation** (v0.10.39, replaces `pad2`).
     See "PR anti-starvation" above.
  2. **`dir_block0_fsb`/`dir_block0_gen` canonical directory block0**
     (write-once per directory incarnation) plus the query/publish API
     `mxfs_dlm_caw_grant_dir_block0()`/`_set_dir_block0()`. Closes a
     directory-conversion double-allocation race that `dir_epoch` alone
     could not (a relative, raceable comparison vs. this absolute
     existence check) — related to, but distinct from, the P150
     inode-cluster-buffer fix that this build's commit message credits as
     the double-alloc root fix.
  3. **`caw_inode_fastpoll`** (v0.10.39, default on) — fixed 2ms poll for
     the first `MXFS_CAW_INODE_FASTPOLL_MS` (64ms) of an inode wait,
     replacing the exponential-backoff first steps; measured 45→30ms per
     unlink in the 32-node dir_reuse rm storm.
  4. **`caw_epoch_free_reset`** (default on, ccloop cc87fed3 sess7/8
     `dlm_scaling@32` op-rate collapse fix) — clears a freed inode's
     `dir_epoch`/`last_ex_slot` piggybacked on the unlock's existing
     tombstone CAS (zero extra I/O), so a reused inode number doesn't
     inherit its predecessor's stale handoff signal.
  5. **`mxfs_dlm_caw_granted_mode()`** (ccloop cc87fed3 sess3) — real
     per-node mode accessor, added because `mxfs_v5_dlm_inode_granted_mode`
     upgrading in-core mode from a collapsed boolean `mxfs_dlm_caw_held()`
     result could mistake a shared hold for exclusive (RULE-4 proven
     against a fence_during_write@8/caw D-state deadlock).
  6. **`mxfs_dlm_caw_self_held_scan()` / `mxfs_dlm_caw_force_release_self()`**
     (ccloop a864 sess3) — scan-based orphan-bit recovery. See "Additional
     Query/Recovery APIs" above.
  7. **Resource-keyed orphan-clock table** (`ctx->orphan_clock[]`, own
     spinlock) — `mxfs_dlm_caw_orphan_clock_get()`/`_set()`. Replaces
     reliance on per-inode wall-clock fields that get reset on VFS inode
     eviction/reinstantiation faster than a hot churn storm lets them
     accumulate continuous observation.
  8. **`MXFS_CAW_GRANTMETA_SIZE` 4096→32768** — fixes birthday-collision
     wipes of the `releasing`/`grant_seq` unlock-vs-regrant protections at
     32-node scale (339 anchor-less releases observed in one run before
     the fix).
  9. Assorted: dropped the `ino<=256` gate on claim-side instrumentation
     (both mkdir-storm and general forensics were blind above it); minor
     `find_slot`/`caw_slot` hardening.
  Changes: dlm_caw.c, dlm_caw.h.
- 2026-03-24: Fix self-BAST on PR→EX upgrade in mxfs_dlm_caw_lock. The
  is_compatible check at the "compatible — add ourselves" path didn't exclude
  the requesting node's own holder bit. For a PR→EX upgrade, our own PR was
  seen as conflicting with the EX request, bypassing the in-place upgrade and
  falling through to the waiter/BAST path — which BAST'd ourselves. Fix: use
  compatible_excluding_self when our_mode != NL. The code after the compat
  check already handled upgrades correctly (lines 687-693 clear old mode).
- 2026-03-04: Initial implementation — complete module with all 10 API
  functions, BAST poll/multicast, node purge, lock convert, release_all.
  Compiles clean with gcc -Wall -Wextra -Werror.
- 2026-03-04: Heap-allocate lock slot buffers in caw_wait_for_grant,
  mxfs_dlm_caw_lock, mxfs_dlm_caw_unlock, mxfs_dlm_caw_convert,
  mxfs_dlm_caw_release_all, and mxfs_dlm_caw_purge_node to fix kernel
  frame-size warnings (struct mxfs_caw_lock_slot is 512 bytes; two on
  the stack exceeded the 1024-byte limit). Uses goto cleanup pattern
  for consistent free on all return paths.
- 2026-03-05: Yield-on-contention fairness. Added yield_to/yield_set_ms
  fields to lock slot (16 bytes from reserved, now 392 bytes). On unlock
  with waiters, sets yield_to = waiters bitmap so waiting nodes get
  priority over the releasing node. Non-priority nodes back off 10-20ms
  (jittered). 5-second stale yield_to timeout prevents deadlock on node
  death. Adaptive BAST poll: 10ms under contention, 100ms otherwise.
  purge_node and release_all clear yield_to bits. Fixes 8-node starvation
  where some nodes got 0/500 files due to unfair CAW races.
- 2026-03-05: Tuned CAW polling parameters for faster lock handoff under
  contention. POLL_INITIAL_MS: 5->1, POLL_MAX_MS: 100->25, BAST_POLL_MS:
  100->50, BAST_POLL_FAST_MS: 10->5, YIELD_BACKOFF_MS: 10->3. 7-node
  subdirectory test: 3/7 nodes achieved 500/500 (1500/3500 total), 0
  duplicates, 0 panics. 4 nodes had mkdir race bug (directories created as
  regular files under parallel CAW contention). Working nodes achieved ~250
  files/min vs ~5 files/min in flat-dir test (50x improvement). test9 hit
  CAW lock wait timeouts (120s) on inode operations after completion.
- 2026-03-05: Bug 93 fix — CAS MISCOMPARE on empty slot creation. When
  creating a new lock slot (ENOENT path), the compare buffer was zeroed
  (`memset(cur_slot, 0, ...)`), but the empty disk sector could contain
  non-zero data (stale/uninitialized). Changed to `read_slot()` the
  actual disk content for the CAS compare buffer. This was the root cause
  of 100% CAS failure rate that prevented mounting after ungraceful
  shutdown — `find_slot` returned ENOENT because the probe chain was
  intact but the hash didn't match existing slots, and every attempt to
  claim the empty slot failed because the zero-compare didn't match disk.
- 2026-03-06: Bug 95 fix — BAST poll thread unmount hang. The poll thread
  used `mxfs_pal_sleep_ms()` (kernel `msleep()`, uninterruptible) which
  blocked up to 200ms after `ctx->running` was set to false. Replaced with
  condvar timed-wait (`stop_cond`/`stop_lock`). `mxfs_dlm_caw_stop()` now
  signals the condvar after setting `running = false`, waking the poll
  thread instantly. Added `stop_cond` and `stop_lock` fields to
  `mxfs_dlm_caw_ctx`, created in `_create()`, destroyed in `_destroy()`.
- 2026-03-08: Bug 101 fix — node_bit collision causing data corruption.
  `node_bit = 1ULL << local_node` where local_node is a random 32-bit
  node_id (hash of UUID). Shift >= 64 is UB; on x86 masked to node_id%64,
  causing birthday-problem collisions (test1 and test2 both had
  node_id%64=32). Two nodes sharing the same holder bit means the DLM
  grants simultaneous EX locks → uncoordinated writes → zeroed directory
  inodes. Fix: `mxfs_dlm_caw_create()` now takes a `uint8_t node_slot`
  (0-63) from disklock's unique heartbeat slot claiming. `node_bit =
  1ULL << node_slot` is always safe. `purge_node()` also takes `uint8_t
  dead_slot` instead of `mxfs_node_id_t`. Changes: dlm_caw.c/h,
  disklock.c/h (claim_slot, find_node_slot), mount.c (early disklock
  init for CAW, slot lookup in purge). Verified: 4-node 400/400 metadata,
  0 duplicates, 4x64MB data I/O MD5-verified cross-node.
- 2026-03-09: I/O resilience and priority — two improvements for SAN
  latency spikes and high-node-count deployments:
  (1) Transient I/O retry with exponential backoff. `read_slot()` and
  `caw_slot()` now retry up to 5 times on I/O errors (not MISCOMPARE)
  with 10ms initial backoff doubling to 200ms max. Prevents transient
  iSCSI/SAN transport timeouts from failing DLM operations. Logs each
  retry attempt at WARN level for diagnostics.
  (2) Priority I/O for DLM lock operations. New `mxfs_pal_bdev_read_prio()`
  PAL function uses `REQ_PRIO | REQ_SYNC` in kernel to give lock slot
  reads priority over data I/O in the block scheduler. CAW writes already
  bypass the block layer via `scsi_execute_cmd`. This creates effective
  queue separation — lock I/O gets a priority lane so heavy data writes
  from multiple nodes don't starve lock acquisition. New constants:
  `MXFS_CAW_IO_MAX_RETRIES` (5), `MXFS_CAW_IO_BACKOFF_MS` (10),
  `MXFS_CAW_IO_BACKOFF_MAX_MS` (200). Changes: dlm_caw.c/h, pal.h,
  pal_linux_kern.c, pal_linux_user.c.
- 2026-03-09: Bug 102 fix — mount-time stale lock purge. Added
  `mxfs_dlm_caw_purge_dead_nodes(ctx, dead_mask)` which takes a 64-bit
  bitmap of dead node slots and purges all their holder/waiter bits in a
  single pass through 65536 lock slots. Called from mount.c after
  `disklock_claim_slot()` and `dlm_caw_create()` but before `dlm_caw_start()`.
  The dead_mask always includes our own slot (stale bits from a previous
  crashed mount) plus all heartbeat slots that are not ACTIVE. This
  eliminates the 120s DLM lock wait timeout on first access to inodes with
  stale holder bits after ungraceful shutdown. Previously required `mkfs -f`
  to clear. Changes: dlm_caw.c/h, mount.c, mxfs_common.h (version 0.8.0).
- 2026-03-19: Single-node bypass (v0.9.28). When no peers exist, CAW DLM
  lock/unlock/convert skip disk I/O entirely and operate in-memory. BAST poll
  thread skips disk scanning. On peer discovery (single->multi transition),
  `mxfs_dlm_caw_flush_held_to_disk()` writes all in-memory held locks to disk
  via normal find_slot + CAW path before clearing the bypass flag. New fields:
  `single_node` (bool), `mem_locks[]` (resource+mode tracking array),
  `mem_lock_count`, `mem_lock_mutex`. New APIs: `mxfs_dlm_caw_set_single_node()`,
  `mxfs_dlm_caw_flush_held_to_disk()`. mount.c sets single_node=true at CAW
  start and calls set_single_node(false) in discovery_peer_cb. Changes:
  dlm_caw.c/h, mount.c.
