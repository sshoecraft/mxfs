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
