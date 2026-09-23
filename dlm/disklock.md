# Disklock Module (libmxfs/disklock)

## Overview
Disk-based heartbeat and lock persistence for shared-storage node liveness detection. Provides ~62-second dead-node detection via iSCSI/storage path, completely bypassing TCP/network congestion that affects DLM and UDP lease heartbeats.

The disklock subsystem writes periodic heartbeats and monitors remote heartbeats on the shared block device. When a remote node's heartbeat stalls for ~62 seconds (31 consecutive stale reads @ 2s intervals), disklock fires an expire callback that triggers node purge, SCSI PR preemption, and journal recovery.

## On-Disk Layout
Heartbeat and lock records are stored in a reserved region starting at disklock_offset (mount option).

```
Offset      Region
0           Heartbeat slot 0 (512 bytes)
512         Heartbeat slot 1 (512 bytes)
...
31744       Heartbeat slot 63 (512 bytes)
32768       Lock slot 0 (512 bytes)
33280       Lock slot 1 (512 bytes)
...
```

- **Heartbeat region**: 64 slots × 512 bytes = 32KB (offset 0)
- **Lock record region**: 65536 slots × 512 bytes = 32MB (offset 32768)
- **Total**: ~32MB

Heartbeat slot assignment uses unique claiming: `mxfs_disklock_claim_slot()`
scans all 64 HB slots and claims the first empty one (or re-claims a slot
with our own node_id from a previous mount). The claimed slot index (0-63)
is stored in `ctx->local_slot` and is used as the node's bit position in
CAW DLM holder bitmaps. This guarantees unique bit positions — fixing
Bug 101 where `1ULL << node_id` caused collisions for node_ids >= 64.

Lock records use FNV-1a hash + linear probing for resource lookup.

## Record Structures

### Heartbeat Record (512 bytes, exactly)
```c
struct mxfs_disklock_heartbeat {
    uint32_t  magic;            /* MXFS_DISKLOCK_MAGIC (0x4D584C4B) */
    uint32_t  flags;            /* MXFS_DISKLOCK_FLAG_ACTIVE = 1 */
    uint32_t  node_id;          /* Writing node ID */
    uint32_t  pad;
    uint64_t  timestamp_ms;     /* Wall-clock time when written */
    uint64_t  epoch;            /* Node reboot epoch for detection */
    uint64_t  lock_count;       /* DLM lock count snapshot */
    uint8_t   reserved[472];
};
```

### Lock Record (512 bytes, exactly)
```c
struct mxfs_disklock_record {
    uint32_t               magic;           /* MXFS_DISKLOCK_MAGIC */
    uint32_t               flags;           /* MXFS_DISKLOCK_FLAG_ACTIVE = 1 */
    struct mxfs_resource_id resource;      /* Inode + extent + AG info */
    uint32_t               owner;           /* Node ID holding the lock */
    uint8_t                mode;            /* DLM mode (PR, PW, etc) */
    uint8_t                state;           /* MXFS_LSTATE_GRANTED */
    uint8_t                pad[2];
    uint64_t               granted_at_ms;   /* Grant timestamp */
    uint64_t               epoch;           /* Owner's epoch */
    uint8_t                reserved[448];
};
```

## Heartbeat Thread (disklock_hb_fn)

Combined write + monitor thread running every 2 seconds (MXFS_DISKLOCK_HB_INTERVAL_MS).

### Write Path
1. Build local heartbeat record with current timestamp, epoch, lock_count
2. Write to claimed heartbeat slot (ctx->local_slot, unique 0-63)
3. All nodes immediately see the fresh heartbeat via block device

### Monitor Path
For each monitored slot (tracked in monitored[]):
1. Read remote heartbeat from disk
2. Compare timestamp to last_timestamp
3. Track changed_samples (fresh reads) vs equal_samples (stale reads)
4. Detect epoch changes (immediate DEAD → node rebooted)
5. Trigger expire callback when DEAD_THRESHOLD reached

Monitor logic per remote node:
- **LIVE threshold**: 2 consecutive fresh reads (changed_samples >= 2)
- **DEAD threshold**: 31 consecutive stale reads (equal_samples >= 31) @ ~62 seconds
- **Epoch change**: Immediate DEAD declaration (node rebooted without graceful shutdown)

Example timeline:
```
T=0s:   node_id=2, timestamp=1000ms, epoch=5
T=2s:   timestamp=1002ms (fresh), changed_samples=1, equal_samples=0
T=4s:   timestamp=1004ms (fresh), changed_samples=2 → LIVE
T=6s:   timestamp=1004ms (stale), changed_samples=0, equal_samples=1
...
T=62s:  timestamp=1004ms (stale), equal_samples=31 → DEAD, fire callback
```

Allocated buffers (hb, rhb) on heap to avoid kernel stack frame warnings (1024+ bytes on stack).

## Three Death Detection Paths

MXFS uses three independent, overlapping mechanisms to detect node failure:

| Path | Speed | Mechanism | Bypass |
|------|-------|-----------|--------|
| **TCP disconnect** (peer.c) | Seconds | Socket error in DLM transport | Network routing issues only (rare) |
| **Disklock heartbeat** (disklock.c) | ~62s | Storage I/O, block device visible to all nodes | Storage outage (affects all nodes) |
| **UDP lease** (lease.c) | ~10 min | Multicast heartbeat + UDP ACKs | Multicast filtering or network storm |

All three paths use a per-peer cooldown (30s in mount.c) to prevent duplicate processing of the same failure.

## Lock Records (Currently Unused)

Lock record write/clear/read functions are fully implemented but not called by mount.c:
- `mxfs_disklock_write_grant()` — writes lock record at FNV-1a hash slot
- `mxfs_disklock_clear_grant()` — clears lock record
- `mxfs_disklock_read_all()` — scans all 65536 slots, returns active records

Reserved for future DLM lock persistence (crash recovery without requiring all peers online).

## Key Functions

**Lifecycle:**
- `mxfs_disklock_create(dev, offset, node_id)` — allocate context, initialize
- `mxfs_disklock_destroy(ctx)` — cleanup, stop heartbeat

**Slot Claiming (Bug 101 fix):**
- `mxfs_disklock_claim_slot(ctx)` — scan 64 HB slots, claim first empty, return slot 0-63
- `mxfs_disklock_get_slot(ctx)` — return claimed local_slot
- `mxfs_disklock_find_node_slot(ctx, node_id)` — find which slot a given node occupies (in-memory first, disk fallback)

**Heartbeat Control:**
- `mxfs_disklock_start_heartbeat(ctx)` — spawn disklock_hb_fn thread
- `mxfs_disklock_stop_heartbeat(ctx)` — broadcast shutdown_cond, join thread

**Expiry Callback:**
- `mxfs_disklock_set_expire_cb(ctx, cb, data)` — register death detection callback
- Callback fired from disklock_hb_fn when node transitions to DEAD state

**Per-Node Monitoring:**
- `mxfs_disklock_monitor_node(ctx, node_id)` — find peer's slot on disk, enable monitoring
- `mxfs_disklock_unmonitor_node(ctx, node_id)` — disable monitoring using slot_node_id mapping
- `mxfs_disklock_purge_node(ctx, node_id)` — clear all heartbeat + lock records owned by dead node

**Lock Records (unused):**
- `mxfs_disklock_write_grant()` — write lock record
- `mxfs_disklock_clear_grant()` — clear lock record
- `mxfs_disklock_read_all()` — scan all lock records

## Integration Points (mount.c)

Discovery callback → monitor_node:
```c
discovery_peer_cb() → mxfs_disklock_monitor_node()
```

Peer connect callback → monitor_node:
```c
peer_connect_cb() → mxfs_disklock_monitor_node()
```

Remove callback → unmonitor_node:
```c
remove_node() → mxfs_disklock_unmonitor_node()
```

Disklock expiry → purge + DLM cleanup + SCSI PR preempt + journal recovery:
```c
disklock_expire_cb() → {
    mxfs_disklock_purge_node(disklock)      /* clear records */
    purge_node_dlm(dlm)                     /* fail pending locks */
    mxfs_scsipr_preempt(scsipr, dead_node)  /* fence SCSI PR */
    mxfs_journal_dead_peer(journal)         /* trigger recovery */
}
```

All three death paths (TCP, disklock, lease) converge on this same purge_node_dlm/scsipr_preempt sequence.

## Mount Option

`disklock_offset=<bytes>` — byte offset on shared device where disklock region starts

Example:
```bash
mount -t mxfs -o disklock_offset=33554432 /dev/sdb /mnt/shared
```

If not specified (disklock_offset=0), disklock is not initialized (mnt->disklock remains NULL).

## Shutdown Sequence

`mxfs_disklock_stop_heartbeat()`:
1. Set `running = false`
2. Lock shutdown_lock, broadcast shutdown_cond
3. Unlock shutdown_lock (wakes disklock_hb_fn from timedwait)
4. **Bug 99 (amended 2026-07-18)**: `mxfs_pal_thread_join_timeout(5000)` is the FAST PATH only. On timeout the stop now ESCALATES to a blocking `mxfs_pal_thread_join` instead of abandoning the thread: an abandoned kthread still runs module code and owns an in-flight 512B heartbeat bio, and after rmmod its completion jumps into unmapped module text (the recurring `Unable to access opcode bytes at 0xffffffffc1...` bio_endio panics, 4-20 per node in serial history; `end_clone_bio` frames on the dm-multipath rig). The stuck write is bounded by the guest SCSI command timeout + error handling (~180s+EH), so the blocking join is slow-but-terminating; a slow unmount beats a delayed crash.

The heartbeat thread checks the `running` flag between each I/O call (heartbeat write, remote heartbeat read, monitoring logic), allowing prompt exit even when individual I/O calls complete normally.

**IMPORTANT**: In `mxfs_unmount()`, peer shutdown MUST happen BEFORE disklock destruction (Bug 100). Peer recv threads call `peer_disconnect_cb` → `disklock_purge_node` during disconnect handling. If disklock is freed while recv threads are still running, `purge_node` hits freed memory (use-after-free). Correct unmount order: peer_shutdown → disklock_stop_heartbeat → disklock_destroy.

## Ported From
kernel/mxfs_disklock.{c,h} — kernel file I/O (filp_open, kernel_write/read) replaced with PAL bdev_read/bdev_write. delayed_work replaced with PAL thread.

## Files
- disklock.h: 145 lines — record structs, context, public API, constants
- disklock.c: 732 lines — implementation

## History
- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-19: Fixed unmount hang — replaced uninterruptible sleep with condvar timed wait in heartbeat thread; stop() broadcasts condvar before joining
- 2026-03-04: Fixed frame size warning in disklock_hb_fn() — moved both 512-byte heartbeat buffers (hb for write path, rhb for monitor path) from stack to heap via mxfs_pal_alloc(). Combined 1024+ bytes on stack exceeded kernel frame limit.
- 2026-03-04: Added per-node monitoring thread integrated into heartbeat thread, epoch change detection, expire callback, SCSI PR preempt on death, disklock_offset mount option
- 2026-03-04: Bug 86 fix -- peer_connect_cb (inbound TCP accept path) was missing mxfs_disklock_monitor_node() call. Peers that connected inbound (without going through discovery_peer_cb) were never added to the monitored[] array, so the heartbeat monitor loop skipped them entirely. Fix: added disklock_monitor_node call in peer_connect_cb alongside lease_register_node, matching discovery_peer_cb.
- 2026-07-18 (ccloop 72513a13): Bug 99 AMENDMENT -- never abandon the heartbeat thread. Timed join stays as the fast path, but timeout now escalates to a blocking join (see item 4). Root-caused the recurring after-rmmod bio_endio crashes into unloaded module text to the abandonment path.
- 2026-03-08: Bug 99 fix -- unmount hang in disklock_stop_heartbeat. Root cause: heartbeat thread stuck in blocking disk I/O (e.g., iSCSI timeout), thread_join waits forever. Fix: (1) heartbeat loop checks `running` flag between each I/O call, (2) new `mxfs_pal_thread_join_timeout(5000)` replaces blocking join — logs warning and continues if thread doesn't exit within 5s. Changes: disklock.c, pal.h, pal_linux_kern.c, pal_linux_user.c.
- 2026-03-08: Bug 100 fix -- use-after-free in disklock_purge_node during unmount. Root cause: unmount destroyed disklock BEFORE shutting down peer networking. Peer recv threads still running could call peer_disconnect_cb → disklock_purge_node on freed memory. Crashed with `preempt_count 1` in `mutex_unlock` inside `mxfs_disklock_purge_node`. Fix: (1) moved peer_shutdown BEFORE disklock_stop/destroy in mxfs_unmount(), (2) added `!mnt->mounted` early-return guard in peer_disconnect_cb, disklock_expire_cb, and lease_expire_cb. Changes: mount.c.
- 2026-03-10: Bug 108 fix -- disklock expire callback reported wrong node_id ("node 0" instead of actual). Root cause: expire callback passed rhb->node_id from the heartbeat sector read, but when the sector was already zeroed (by disklock_purge_node from peer_disconnect_cb path) or the read failed, rhb->node_id was 0. Fix: use ctx->slot_node_id[slot] (populated by monitor_node at discovery time) as the authoritative node_id for the expire callback. This is reliable regardless of on-disk heartbeat state. Changes: disklock.c (disklock_hb_fn expire callback).
- 2026-03-08: Bug 101 fix -- unique heartbeat slot claiming. Old approach:
  node_id % 64 caused collisions (e.g. test1 node_id=527944736 and test2
  node_id=3065900128 both mapped to slot 32). New: claim_slot() scans all
  64 HB slots and claims the first empty one. Re-claims own node_id from
  previous mount. local_slot stored in ctx, used for heartbeat writes and
  as CAW DLM node_bit. Added find_node_slot() for reverse lookup (used by
  monitor_node, unmonitor_node, purge in mount.c). monitor_node now finds
  actual slot on disk instead of using node_id%64. unmonitor_node uses
  slot_node_id[] in-memory mapping. purge_node scans HB area for actual
  slot. Changes: disklock.c/h, dlm_caw.c/h, mount.c.


## sess436 — zero-epoch read is not a change of hands (0.41.9)

`tests/d_recov_zero_epoch_verify.sh` (0.41.8) proved that an ACTIVE record read
with `epoch=0` took the monitor's epoch-change arm (`!inc_eq(0, cached)`), fired
the death as a restart and rebased the cache to 0 at `rebase_only`; every
detector then lacked fencing authority (`P238-FENCE-NOINC inc 0`) and the
restored real epoch read as another restart — the elected replayer looped
`NOT replayed — no proven exclusion (-61)` forever.  The arm now routes a zero
read on a known incarnation through `hb_rebase_epoch` (retain, `P-HB-INC-ZERO`
once per episode via `node_track.inc_zero_logged`) and falls through to the
timestamp arms, so the record expires on the cached incarnation.

## sess437 — a zero epoch is not a successor tenancy either (0.41.11)

The 0.41.9 arm held on the rerun (`P-HB-INC-ZERO` retained the cached
incarnation, the death was declared under the real one), but the run still
failed for two reasons downstream of the monitor:

1. `hb_still_dead_stamp()` (the pending sweep's "recovered or rejoined"
   discriminator) treated a same-node record at a *different* incarnation as
   a successor tenancy.  Epoch 0 satisfied it, so two seconds after the death
   every survivor logged `P163-RECOVERED … running deferred local purge` with
   **no replay**, cleared the pending marker (every later acquire `-ENODATA`)
   and purged the victim's grants.  A claim never publishes epoch 0
   (`hb_draw_incarnation` fails closed), so a same-node record whose epoch is
   not valid is a torn/stale image of the victim: the predicate now returns
   *still dead* for it and only a VALID different incarnation lifts the barrier.
2. Nothing re-tried the fence once the platter read the real incarnation
   again: `P238-FENCE-ZEROINC` refuses to lay the intent, and the P304 retry
   latch re-drives only a standing attempt.  `mxfs_v5_dlm_recovery_acquire`
   now re-drives the fence itself (`P238-FENCE-REDRIVE`) when the claim finds
   no descriptor and `recovery_slot_status` says `UNFENCED` (ACTIVE, still this
   victim, valid epoch), then claims again.

Verification: `tests/sess437_chain12_04111_takeover_zeroinc.sh` (zero-epoch arm
must reach `foreign replay of slot S … complete` with zero `P163-RECOVERED`
before it).

## sess438 — 64-bit per-boot PR key + host/boot identity block (0.43.0)

`docs/whole-cluster-restart.md` item 2 (design-consult ruling: `docs/rulings/prkey64-item2-ledger-not-deferrable.md`).
The PR key was the 32-bit `node_id` and fencers derived the victim key from
a node id.  Now:

- **Layout (proto_gen 12).**  Evict ring 23 → 19 entries (union 384 → 320);
  `struct mxfs_hb_identity` (64 B) at offset 360: `{magic "MXID", ver,
  key_gen, host_uuid[16], boot_uuid[16], pr_key, host_src, crc32c,
  reserved[8]}`.  Tail unchanged (prov 424 / mepoch 456 / feat 500).  The
  crc binds `{slot, flags, fs_gen, node_id, epoch}` too (`hb_ident_crc`), so
  a block cannot be transplanted across slots, roles or incarnations.
- **Stamped** by `hb_ident_fill()` on every record this incarnation writes:
  heartbeat, both claim paths, WITHDRAWN (a late monitor may only ever see
  that one), GUARD (names the guard WRITER — never consulted for a victim).
  Installed by `mxfs_disklock_set_identity()` before the claim (`-EBUSY`
  once a slot is held: uniform across the tenure, like snlocal).
- **Observed** by the monitor on every read (`hb_ident_observe`): ACTIVE or
  WITHDRAWN records with a valid block, frozen per exact `(node_id, epoch)`
  in `ident_obs[slot]`.  A different key for a frozen tuple is
  `P-PRKEY-CONFLICT` (protocol violation; the tuple is poisoned — no fence by
  key from this node).
- **Frozen into the death snapshot** at `fire_dead` (`hb_ident_freeze_victim`
  → `pending_key*[slot]`) BEFORE `expire_cb` and before `rebase_only` can
  adopt a successor.  `mxfs_disklock_victim_key(slot, node, epoch)` serves
  ONLY that snapshot, only for the exact tuple; 0 ⇒ the fencer refuses
  (`MXFS_FENCE_KIND_NO_VICTIM_KEY`, `P-PRKEY-FENCE-REFUSED`), never derives a
  key from `node_id`.  `P-PRKEY-VICTIM-UNKNOWN` is printed at freeze time
  when nothing was observed for the tuple.
- **Key selection** lives in `dlm/prledger.{c,h}` (new envelope region,
  `MXFS_FORMAT_F_PRKEY64`): one 512 B CAS-written entry per registrant;
  `mxfs_prledger_select()` reuses this boot's entry on this LUN if one exists
  (`P-PRKEY-REUSED`), else draws a key ≥ 2^32, checks READ KEYS once per
  candidate + the ledger's owned entries, and CASes a reusable entry to
  PREPARED (`P-PRKEY-SELECTED`) BEFORE `REGISTER`; `REGISTER` is verified by
  READ KEYS (`P-PRKEY-REGISTERED`, else `P-PRKEY-REGISTER-UNVERIFIED` fails
  the mount) and the entry moves to REGISTERED; clean unregister → RETIRED;
  a certified PREEMPT AND ABORT → FENCED (`P-PRKEY-FENCED`).  A REGISTERED
  entry whose key READ KEYS no longer holds is reusable
  (`P-PRKEY-STALE-ENTRY`); PREPARED entries are never swept.
- **Fence plumbing** (`v5_mount.c`): the intent, the P&A and the certificate
  all use the frozen key; slotless (lease-only) victims and the bare fence
  look the node up in the ledger (`mxfs_prledger_key_of_node`); the vergate
  fences a LEGACY/MISMATCH record by `node_id` (that protocol's key) and a
  CORRUPT one by ledger lookup.
- **Tools.**  `mkfs_mxfs` lays the region out after tauth (256 × 512 B,
  zero-filled = FREE) and sets the flag; `chk_mxfs` validates the region,
  prints owned entries, and decodes/validates each ACTIVE/WITHDRAWN
  record's identity block; `tests/hb_epoch_inject.py` reseals the identity
  crc when it rewrites an epoch.
- **Not yet built into this**: predecessor-boot self-replacement (item 3) —
  `P305-PR-PREDECESSOR-KEY-PRESENT` still refuses; the identity block and the
  ledger are what item 3 will decide on.

## sess450 (0.59.0): RETIRE_PENDING — the two-phase departure's durable handoff

D-CLEAN-RELEASE-THEN-UNREGISTER-FAIL-LEAVES-UNFENCEABLE-STALE-REGISTRANT-0356
and phase (ii) of D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377.  The sess449
design-consult review of 0.58.0 (re-stamp RELEASED → WITHDRAWN on a failed
unregister) found it insufficient: EMPTY was published BEFORE the key was
proven absent, so a crash (or a re-stamp that never lands) between the
release and the unregister left a reusable EMPTY slot next to a still-
registered key that nothing names.  Now:

- **Flag 4, `MXFS_DISKLOCK_FLAG_RETIRE_PENDING`.**  `mxfs_disklock_release_slot`
  CASes the node's own final ACTIVE image with `flags` moved to
  RETIRE_PENDING and the identity crc re-bound (`hb_ident_fill`; the crc
  covers flags).  Identity, epoch, provenance and `ident.pr_key` are kept.
  `P304-RETIRE-PENDING-RELEASED`.
- **Non-consumable.**  Both claim paths skip it
  (`P274-CLAIM-RETIRE-PENDING-SKIP`); `hb_ident_observe` accepts it (a
  first-sight peer can still freeze the key for a fence); the join gate,
  vergate and membership key on ACTIVE and never see it.
- **Settled by the monitor** (`hb_retire_settle`, first sight, tracked or
  not, in the pending-victim block, the main first-sight arm and the
  dead-confirm arm): FUA re-read; key = the record's identity block (or the
  frozen observation); `ctx->key_present_fn` (v5: READ KEYS via
  `mxfs_scsipr_key_present`; a mount without a PR ctx answers PRESENT for a
  nonzero key — fail closed).  Absent → CAS to EMPTY, identity crc
  re-bound (`P304-RETIRE-COMPLETED-BY-PEER`) and the ordinary
  `P163-CLEAN-DEPART` arm retires the tracking.  Present → the grace runs
  from first sight on this node's uptime clock (`retire_seen_*[slot]`,
  keyed to the exact incarnation); within `MXFS_DISKLOCK_RETIRE_GRACE_MS`
  (30 s = PR verify deadline + lap + margin) the slot is skipped for the
  lap (it never counts toward the stale window — the release stopped the
  heartbeat on purpose); past it → CAS to WITHDRAWN
  (`P304-RETIRE-EXPIRED-WITHDRAWN`) and the sess9 withdraw pipeline fences
  the key, replays the clean slice and purges the slot.  Only `flags`
  moves in either CAS.
- **Departing node.**  Unregister OK → nothing (a de-registered initiator
  cannot write a WE-RO LUN; peers or the next mount complete it).
  Unregister failed → `P303` re-stamp RETIRE_PENDING → WITHDRAWN (0.58.0
  code; the accepted-image predicate is now RETIRE_PENDING|ACTIVE — an
  EMPTY image means a peer already proved the key absent).  No PR target
  (`-EOPNOTSUPP`) or no key at all → `mxfs_disklock_retire_complete_self`
  CASes RETIRE_PENDING → EMPTY (`P304-RETIRE-COMPLETED-SELF`).
- **Same-host predecessor scan** (`v5_mount.c` P305): a RETIRE_PENDING
  record of this boot is a dirty predecessor exactly like WITHDRAWN.
- **Tools.**  `chk_mxfs` decodes flag 4 in `check_disklock`,
  `--show-quarantine` and the repair table (BLOCKED: a live peer settles it).
- **Test.**  `tests/pr_unregister_fail_restamp.sh <N> <victim> [probe] [mode]`:
  `restamp` (0.58.0 arm + the clean-path control: a peer completes the
  retirement, no fence, key table shrinks by one) and `crash`
  (`dbg_retire_skip_restamp=1` one-shot skips the P303 re-stamp: peers must
  see, expire and fence on their own).  Chain 69 runs both.
- **Not done (D-377 items 2-4):** local quarantine/refuse-remount policy on a
  failed retirement (currently alert + handoff), admission rejection of a
  multipath `reservation_key` config, operator `chk_mxfs --preempt-key`.

## sess451 (0.59.1): the STOP-SHIP fixes to the RETIRE_PENDING settlement

The sess450 design-consult review (ccmemory `ccloop-c7ee71c6-sess450-GPT-ruling-
0590-retire-pending-STOP-SHIP`) found three defects and one regression in the
above.  What changed:

- **`hb_retire_settle(ctx, slot, off, rhb, immediate)`** — the key lookup is
  `ctx->key_state_fn` (typedef `mxfs_disklock_key_state_fn`, tri-state +
  OWN; `mxfs_disklock_set_key_state_fn`).  Key naming: valid identity block
  → `ident.pr_key`; else the frozen observation of this EXACT incarnation;
  else UNKNOWN ("unnamed" is not "no key").  A valid identity whose key
  disagrees with the frozen observation of the same incarnation is
  `P304-RETIRE-KEY-CONFLICT` → UNKNOWN.  Only a valid identity that records
  key 0 (no PR on that transport) is "nothing to retire".  Outcomes:
  ABSENT/OWN → EMPTY (`P304-RETIRE-COMPLETED-BY-PEER ... state=… via=…`);
  PRESENT inside the grace → WAITING, past it (or `immediate`) → WITHDRAWN
  (`P304-RETIRE-EXPIRED-WITHDRAWN ... immediate=N`); UNKNOWN → WAITING
  forever, `P304-RETIRE-UNKNOWN-STALLED` once per grace per slot
  (`retire_unknown_log_ms[]`).  The `known` flag is gone: UNKNOWN never ages
  into WITHDRAWN.
- **`hb_retire_reread`** — a CAS lost with `-EAGAIN` FUA re-reads the sector
  into `*rhb` before returning CHANGED; a failed re-read returns the errno.
  The dead-confirm arm now treats CHANGED like WAITING (`equal_samples=0;
  continue`): the sector moved under us, so nothing there is a stale-dead
  image of `victim_node`; the next lap's plain read classifies it.  The
  pending-victim block and the first-sight arm were already safe once the
  image is fresh.
- **`mxfs_disklock_retire_settle_slot(ctx, slot, immediate)`** — the mount
  thread's entry: reads the slot, `-ENOENT` unless it is a RETIRE_PENDING
  record of this filesystem, else the settlement above.
- **`mxfs_disklock_get_recovery_pending_slots(..., out_retire_mask)`** —
  RETIRE_PENDING is the third requires-recovery shape (bit + identity +
  the new mask).  `mxfs_v5_dlm_mount_pending_recovery` settles each
  immediately: EMPTY retires the bit, WITHDRAWN keeps it with identity (the
  ordinary withdrawn-death pipeline), anything else keeps it WITHOUT
  identity (fail-closed, `P-ADMIT-RETIRE-PENDING-HELD` once per slot per
  mount).
- **v5 side** — `v5_disklock_key_state` (no PR ctx → UNKNOWN; our own
  derived key → OWN iff READ KEYS shows it present; else the scsipr
  tri-state); installed right after `mxfs_disklock_create` on both
  transports.  `mxfs_scsipr_key_state` + a 1 s READ KEYS/RESERVATION
  snapshot (`snap_*`, `snap_lock`) in the scsipr ctx: ABSENT needs a
  complete view + our key in it + the WE-RO/WE-AR reservation in force
  (`P-PR-ABSENCE-UNPROVABLE` once per 30 s otherwise).
- **P305** — `v5_same_boot_scan(ctx, hid, refuse_dirty)` runs on EVERY CAW
  mount; a RETIRE_PENDING record of this boot is recorded
  (`p305_retire_slot`, `P305-PR-SAME-BOOT-RETIRE-PENDING`) and settled by
  `v5_p305_settle_retire_pending` after the disklock exists: EMPTY →
  `P305-RETIRE-SETTLED`; WITHDRAWN (present key not ours) →
  `P305-RETIRE-KEY-FOREIGN-PRESENT`, refuse; WAITING (UNKNOWN) →
  `P305-RETIRE-UNSETTLED`, refuse; CHANGED/-ENOENT → rescan (≤4).
- **Departure lock** — `mxfs_v5_dlm_departure_lock/unlock` (host-wide,
  created by `mxfs_v5_dlm_global_init` from `init_xfs_fs`): put_super's
  late phase and the failed-mount unwind hold it across release → unregister
  → re-stamp/complete → finish; the CAW mount holds it from REGISTER through
  the P305 settlement (`ctx->departure_locked`, released on the error path
  after the unregister).
- **Tests.**  `tests/retire_pending_admission.sh <N> <victim> <joiner>
  [probe] sameboot|joiner`; chain 70 (`tests/sess451_chain70_retire_pending.sh`)
  runs restamp, crash ×2, sameboot ×2, joiner.
- **Still owed** from the ruling's list: criterion 7 (prohibit clustered
  no-PR mode — D-0359's domain; `retire_complete_self` on `-EOPNOTSUPP`
  remains for the lone/no-PR device), the D-377 items 2 and 4, and a
  deterministic negative arm for UNKNOWN (no READ KEYS fault injector yet).

## sess452 (0.59.2): STOP-SHIP #2 — bracketed proof, probe thread, P305-only OWN, key-0, quiescence

The sess451 design-consult review (ccmemory `ccloop-c7ee71c6-sess451-GPT-ruling-0591-
retire-settlement-STOP-SHIP-2`) ruled 0.59.1 STOP-SHIP on five blockers.
Disklock-side changes:

- **`hb_retire_settle`** — two callbacks: `key_state_fn` (ASYNC; the
  monitor's three arms, `immediate=false`) and `key_state_sync_fn`
  (`mxfs_disklock_set_key_state_sync_fn`; `immediate=true` — the admission
  barrier and P305 on the mount thread).  There is no OWN: the enum is
  ABSENT / PRESENT / UNKNOWN and only ABSENT publishes EMPTY.  A valid
  identity recording key 0 is `key0-invalid` → UNKNOWN (0.59.1 published it
  EMPTY).
- **`mxfs_disklock_retire_settle_own(ctx, slot, node, epoch, key, proof)`** —
  the P305-only path: FUA read, exact `{slot, node, epoch}` RETIRE_PENDING
  record with a valid identity whose `pr_key == key`, CAS to EMPTY
  (`P305-RETIRE-SETTLED-OWN ... proof=`); anything else CHANGED
  (`P305-RETIRE-OWN-CHANGED`, `P305-RETIRE-OWN-CAS-LOST`), nothing written.
  The caller holds the departure lock and has already obtained the proof it
  names (`own-registration-bracket` from `mxfs_scsipr_own_registration_
  proven`, or `single-node-exclusive-topology`).
- **`mxfs_disklock_retire_complete_self`** is unchanged but its v5 caller
  (`mxfs_v5_dlm_slot_retire_complete`) refuses unless the mount was admitted
  under `single_node_exclusive` / `fence_capability_override`
  (`late->self_retire_ok`): `P304-RETIRE-SELF-REFUSED-CLUSTERED`.

scsipr side (`dlm/scsipr.c`): `scsipr_bracket_run` (A / RESV / B, one
generation, own key in both, WE-AR held → `proof`; `why` names the missing
leg), `scsipr_bracket_and_commit` (under `probe_lock`; committed under
`snap_lock` unless `snap_inval_seq` moved → `P-PR-BRACKET-DISCARDED`;
`P-PR-BRACKET-INCOHERENT` when the generation moved), `scsipr_answer`
(PRESENT ≤ 2 s; ABSENT only with `proof`, ≤ 5 s, once per (key, `snap_seq`)
via `absent_used[]`; else UNKNOWN + `P-PR-ABSENCE-UNPROVABLE` once/30 s),
`mxfs_scsipr_key_state` (async: answer + `probe_kick`),
`mxfs_scsipr_key_state_sync` (mount thread: bracket then answer,
`P-PR-KEY-STATE-SYNC`), `mxfs_scsipr_own_registration_proven`
(`P-PR-OWN-PROOF`), `mxfs_scsipr_snap_invalidate` (after every PROUT and from
`v5_resv_conflict_cb`), `mxfs_scsipr_probe_start/stop` + `scsipr_probe_fn`
(brackets on kick, ≥ 250 ms apart, 50 ms idle slices; started right after
the key-state callbacks are installed, stopped by `mxfs_v5_dlm_detach_pr_key`
under the new `keystate_lock` before the context is freed).  `scsipr_free`
also fixes the 0.59.1 leak of `snap_lock`/`snap_keys` in `mxfs_scsipr_abandon`.

v5 side: `p305_retire_mask` + `p305_retire_{node,epoch,key}[64]` replace the
single slot; `v5_p305_settle_retire_pending` settles each record by its key
class (own key → proven + settle_own; key 0 → topology or refuse; other →
immediate settlement), rescans on CHANGED (≤ 4 rounds).

Quiescence (xfs side): `m_mxfs_departure_stage`, `m_mxfs_buf_io_inflight`,
`m_mxfs_io_after_freeze`, `b_mxfs_io_counted`; `mxfs_departure_quiesced`
in `xfs_super.c` gates `mxfs_v5_dlm_slot_release_commit` in put_super and
the failed-mount unwind.

Verification: `tests/retire_pending_admission.sh` arms unknown / unknownresv
/ trunc / slowpr / joinerunk / race / genmove / multipending;
`tests/sess452_chain71_retire_pending.sh`.

## 0.59.4 (sess453) — certified fence descriptor fires the death on first sight (D-0519)

The monitor had a first-sight arm for a WITHDRAWN stamp (sess182) but none
for the state that stamp becomes within milliseconds: the prover's
`FLAG_RECOVERY_GUARD` record carrying the certified descriptor.  A peer that
missed the ~8 ms WITHDRAWN window (every non-prover peer, on a 2 s lap)
classified the GUARD record as *inactive* and counted 31 equal samples —
62 s — before `fire_dead`; the elected replayer (lowest live slot) is almost
never the prover, so a fenced node's slice replay and purge waited a minute,
and at full slot occupancy its own rejoin was refused `P300-CLAIM-EXHAUSTED`
meanwhile (chain 72: certificate 5169.0, "heartbeat expired after 31 checks"
5230.6, `P163-RECOVERY-COMPLETE` 5262.2).  New arm, after the WITHDRAWN arm:
a GUARD record whose validated descriptor is at stage ≥ FENCED, names this
slot and a valid victim incarnation, is FUA-confirmed and fired
(`P163-FENCED-SEEN slot node inc prover stage`) exactly like WITHDRAWN —
`expire_cb` marks it pending, `v5_handle_node_death` finds the certificate
(`P238-FENCE-DONE`) and dispatches the election.  Once per (victim,
incarnation) per slot (`fenced_seen_node/epoch`); an attempt still at stage
< FENCED and a refused pending mark keep the 31-sample backstop.

## 0.60.0 (sess453/454) — no CAW emulation anywhere in the record table

design-consult review #3 condition 8 / design ruling D7 and its companion (see
`docs/pr-fencing-departure.md`, "0.60.0 — landing group 1").  Every
`-EOPNOTSUPP` from `mxfs_pal_bdev_compare_and_write` on a heartbeat-table
record used to degrade to `write_sector_fua` — sometimes with a
read-verify (heartbeat, guard refresh/zero) or a read-back confirm
(recovery milestone, guard lay), sometimes bare (release, withdraw, the
settlements).  All of them are an unconditional overwrite of a sector that
may have moved since the confirming read, which is the race the CAS exists
to lose safely.  They are replaced by `hb_cas_nocaw_locked()` /
`hb_cas_nocaw()`: log `P304-CAS-NOCAW slot= op=` once per slot
(`retire_nocaw_logged[]`), leave the record unchanged, and return the CAS
error to the caller, which treats it as "not this lap" (settlements),
"indeterminate" (heartbeat — the lease runs out and the peers fence us),
"release/withdraw failed" (departure), or "re-read and re-decide" (recovery).
Reachability: P311 (D-0359) refuses a CAW-transport mount whose lock-slot
CAS is not operational and the TCP transport is refused for clustered RW,
so these arms fire only on runtime CAW loss.  `claim_slot_noncaw` is the
one surviving non-CAS write: an EMPTY sector, before admission.

## 0.61.0 (sess454) — the ABSENT settlement leaves the heartbeat thread

`hb_retire_settle` no longer CASes a RETIRE_PENDING record to EMPTY from
a key-state table answer.  Monitor mode: the async table still answers
PRESENT (grace → WITHDRAWN as before); anything else for a nonzero named
key is handed to `ctx->settle_absent_fn(…, immediate=false)`, which
enqueues it for the owner's retire settle worker and returns WAITING (the
UNKNOWN-stalled escalation keeps running meanwhile).  Immediate mode (the
mount thread's P305 / admission sweep) calls the same callback inline; it
answers EMPTY / CHANGED / PRESENT / WAITING, and PRESENT falls into the
immediate WITHDRAWN rule.  The CAS itself is the new
`mxfs_disklock_retire_cas_empty()`: FUA re-read, byte-identical to the
image the proof was obtained for, `validate_fn` (the scsipr proof-token
consume) adjacent to the compare-and-write, then EMPTY; the result
vocabulary gains `MXFS_DISKLOCK_RETIRE_PRESENT` for the callback's answer.
`key_state_sync_fn` is no longer consulted by the settlement (the fresh
bracket now belongs to `mxfs_scsipr_settle_absent`).  See
`docs/pr-fencing-departure.md`, "0.61.0 — landing group 2".

## 0.61.2 (sess456) — the fencing intent names the incarnation it was asked to fence (D-0520)

`mxfs_disklock_recovery_fence_intent()` replaced `recovery_begin()` as the
only descriptor creator but never inherited begin()'s sess86 supersession
predicate: it checked flags, node_id and fs_gen, then copied `cur->epoch`
into `desc.victim_epoch` whatever `victim_epoch` the caller passed.  The
chain 61 nonzero probe (sess448) showed the consequence: the sector was
rewritten E1→E2, every survivor declared E1 dead, and a FENCING descriptor
naming E2 appeared 0.5 s later — a guard on an incarnation nobody observed
stop, with E1's pending recovery stranded behind it for the whole heal
budget and every later prover exiting -ESTALE silently at the descriptor
tuple check.

Now, after the P238-FENCE-ZEROINC refusal and before any sector write:
`!inc_eq(cur->epoch, victim_epoch)` with an ACTIVE record and a valid
feature block at the current proto_gen returns `MXFS_RECOVERY_SUPERSEDED`
(`P237-FENCE-SUPERSEDED`); anything else returns -ESTALE
(`P237-FENCE-INC-MISMATCH`).  Same predicate as
`mxfs_disklock_recovery_slot_status()`, deliberately no weaker.  The
descriptor-present tuple mismatch logs `P237-FENCE-DESC-FOREIGN` with both
tuples.  In `v5_pr_fence_prove_locked` the new SUPERSEDED arm discharges the
pending recovery for the declared incarnation
(`mxfs_disklock_clear_recovery_pending`, retry latch disarmed, blocked-reason
cleared, `P237-FENCE-SUPERSEDED-RETIRED`) exactly as the completion path's
`P237-COMPLETE-SUPERSEDED` arm does, instead of leaving it to re-derive the
same supersession every 30 s.  `tests/incarnation_mismatch_probe.sh` was
rewritten to match the post-sess426 arms and to keep every survivor's
`mxfs:`/`disklock:` line under `tests/evidence/<UTC>_incmis_<arm>/`.

## 0.61.6 (sess460) — hb_caw(): one chokepoint for the record-table CAS

Every exact-image COMPARE AND WRITE of the record table that 0.60.0 made
fail-closed now goes through `hb_caw(ctx, op, what, off, expect, want)`.  In
production it is the PAL call; under the debug bitmask `dbg_cas_nocaw_ops`
(pal/linux/kern.c) the named class returns -EOPNOTSUPP without issuing the
command, which is how tests/cas_nocaw_arms.sh proves, per writer class, that
the sector stays byte-identical and the class fails closed (DIRTY departure +
key retained, record left RETIRE_PENDING, mount refused, recovery not
started) until CAW works again.  Bits: 1 heartbeat, 2 release, 4 withdraw,
8 withdrawn (expiry), 16 restamp, 32 complete-self, 64 empty, 128 settle-own,
256 recovery-milestone, 512 guard, 1024 guard-refresh, 2048 guard-zero.

## 0.63.1 (sess465) — the claim WAITS for transient occupants (D-0523)

**Defect** (D-REJOIN-CLAIM-ENOSPC-DURING-TRANSIENT-SWEEP-GUARD-AT-CAPACITY-0523,
chain 88 guard_race joiner, 32 slices / 32 nodes): a rebooted node could not
mount while a survivor held the transient unclaimed-bucket sweep guard on its
former slot — `mxfs_disklock_claim_slot` pass 2 found no claimable slot and
returned -ENOSPC at once (`P300-CLAIM-EXHAUSTED` / `P300-CLAIM-WITHDRAWN
'retry the mount'`).  Six seconds later the same mount succeeded.

**Rule** (design-consult ruling, `docs/rulings/d0523-claim-wait-transient-guard-at-capacity.md`):
the fix lives in the claim itself.  `hb_claim_wait()` (disklock.c, before
`mxfs_disklock_claim_slot`) runs when pass 2 finds nothing:

- re-reads and classifies the whole table under `ctx->lock` on every lap —
  nothing decided before a sleep survives it; the claim itself is still the
  exact-image CAW of the pass-2 scan that follows a lap;
- **permanent → -ENOSPC** exactly as before (QUARANTINED verdict,
  out-of-range or unreadable/other record, genuinely full, or the operator's
  `single_node_exclusive` assertion): `hb_report_claim_exhausted` prints the
  same diagnostics;
- **waitable** = bucket-sweep guards (no descriptor), recovery leases,
  WITHDRAWN and RETIRE_PENDING records, **with at least one live OTHER
  member**: one absolute deadline `MXFS_DISKLOCK_CLAIM_WAIT_MS` = 181 000 +
  `RETIRE_GRACE_MS` + `HB_INTERVAL_MS` + `GUARD_REFRESH_MS` (disklock.h — the
  181 s is the measured maximum kill→terminal-replay wall over ~100 events in
  16 chain logs, p50 70 s), scans every `HB_INTERVAL_MS` with the lock
  dropped (`mxfs_pal_sleep_ms_interruptible`), `P300-CLAIM-WAIT-START`,
  `-SCAN` every 5 laps, `-DONE` on the claim;
- liveness is CHANGE: an ACTIVE peer is live while its stamp moved within
  `dead_threshold × HB_INTERVAL_MS` (provisionally live on the first scan);
  a sweep guard that stops re-stamping is reported once
  (`P300-CLAIM-WAIT-FROZEN-GUARD`) and left to the live sweeper's
  `hb_guard_abandoned` reclaim; WITHDRAWN / RETIRE_PENDING stay
  byte-identical while a peer works on them, so their only progress is the
  deadline (no change-as-progress for them);
- no live peer before the wait → today's -ENOSPC (a same-host successor
  cannot fence); every peer silent DURING the wait →
  `P300-CLAIM-WAIT-PEERS-LOST`, **-ERESTART**;
- deadline → `P300-CLAIM-WAIT-GAVE-UP`, **-ETIMEDOUT** (transient; never
  -ENOSPC, which reads as permanent);
- the wait consumes none of `MXFS_DISKLOCK_CLAIM_RETRIES` (16) — the loop
  increments `attempt` only on a `P130-CLAIM-RACE` CAW conflict.

### 0.64.2 (sess467) — -ERESTART re-runs the bootstrap in the same mount

Ruling STOP-SHIP 4, second half.  `v5_mount.c` now loops: on
`claim_slot == -ERESTART` it logs `P300-CLAIM-WAIT-RESTART-BOOTSTRAP
attempt=n/N` and jumps back to `v5_bootstrap_run` (the joiner IS the peerless
cluster; the survivor scan's full dead window decides between a total outage
— own it, fence, replay, adopt K — and peers that came back — ordinary claim
and a fresh wait).  The claim-wait state is allocated per `claim_slot` call,
so the restart gets a fresh absolute deadline; nothing was claimed and no
guard is held across the restart.  Bounded by
`MXFS_V5_CLAIM_BOOTSTRAP_RESTARTS` (1): a second peer loss means the
membership churns faster than one dead-window scan can settle, and the mount
fails truthfully with the same -ERESTART (now labelled "after the bounded
in-mount bootstrap restart: retry the mount").

Earlier text for reference (0.63.1 behaviour, superseded): the mount failed
and the NEXT attempt ran the bootstrap.

- (0.63.1 list continues:)
- deadline → `P300-CLAIM-WAIT-GAVE-UP`, **-ETIMEDOUT** (transient; never
  -ENOSPC, which reads as permanent);
- the wait consumes none of `MXFS_DISKLOCK_CLAIM_RETRIES` (16) — the loop
  increments `attempt` only on a `P130-CLAIM-RACE` CAW conflict.

`v5_mount.c` names the two new results in its `claim_slot failed` line.
`tests/guard_race_arms.sh joiner` prints the `P300-CLAIM-WAIT-*` lines and
its availability verdict is the proof (the 180 s artificial hold is below the
budget, so the joiner must mount inside the hold).  Not handled: a signal
during the wait (no PAL signal-pending primitive) — the sleep is
interruptible but the loop re-scans until the deadline.
