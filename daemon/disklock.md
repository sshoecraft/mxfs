# mxfsd_disklock — On-Disk Lock State Persistence

## Overview

The disklock module persists DLM lock state and node heartbeats to a reserved file on the shared XFS volume. This is the VMFS-style approach to lock persistence: lock state lives on the shared block device so it survives daemon restarts and master failover, and provides self-fencing (if you cannot write locks, you cannot write data).

## Files

- `daemon/mxfsd_disklock.h` — public header and data structures
- `daemon/mxfsd_disklock.c` — full implementation

## On-Disk Layout

The lockstate file is located at `<mount_point>/.mxfs/lockstate` and uses the following layout:

```
Offset 0 .. 32767:       Heartbeat region (64 slots x 512 bytes = 32 KB)
Offset 32768 .. end:     Lock record region (65536 slots x 512 bytes = ~32 MB)
Total file size:          ~33 MB
```

### Heartbeat Record (512 bytes)

Each of the 64 heartbeat slots maps directly to a node ID:

| Field          | Type          | Size | Description                      |
|----------------|---------------|------|----------------------------------|
| magic          | uint32_t      | 4    | MXFS_DISKLOCK_MAGIC (0x4D584C4B) |
| flags          | uint32_t      | 4    | 1=active, 0=empty                |
| node_id        | mxfs_node_id_t| 4    | Node that owns this heartbeat    |
| pad1           | uint32_t      | 4    | Alignment padding                |
| timestamp_ms   | uint64_t      | 8    | Monotonic timestamp of last write|
| epoch          | mxfs_epoch_t  | 8    | Epoch at write time              |
| lock_count     | uint64_t      | 8    | Informational lock count         |
| reserved       | uint8_t[472]  | 472  | Padding to 512 bytes             |

### Lock Record (512 bytes)

Lock records are addressed by hashing the resource ID (FNV-1a) modulo 65536, with linear probing for collisions:

| Field          | Type                    | Size | Description              |
|----------------|-------------------------|------|--------------------------|
| magic          | uint32_t                | 4    | MXFS_DISKLOCK_MAGIC      |
| flags          | uint32_t                | 4    | 1=active, 0=empty        |
| resource       | struct mxfs_resource_id | 32   | Locked resource identity |
| owner          | mxfs_node_id_t          | 4    | Node holding the lock    |
| mode           | uint8_t                 | 1    | mxfs_lock_mode           |
| state          | uint8_t                 | 1    | mxfs_lock_state          |
| pad1           | uint8_t[2]              | 2    | Alignment padding        |
| granted_at_ms  | uint64_t                | 8    | When the lock was granted|
| epoch          | mxfs_epoch_t            | 8    | Epoch at grant time      |
| reserved       | uint8_t[448]            | 448  | Padding to 512 bytes     |

## I/O Model

All I/O uses `O_DIRECT | O_SYNC`:

- **O_DIRECT**: Bypasses the page cache for sector-aligned I/O, ensuring writes go directly to disk and are visible to other nodes reading from the shared device.
- **O_SYNC**: Ensures durability — writes are not acknowledged until they hit stable storage.
- **512-byte alignment**: All buffers allocated with `posix_memalign(512)`, all offsets and sizes are multiples of 512 (one hardware sector).

This gives us atomic sector writes: a 512-byte write either lands completely or not at all.

## Hashing and Collision Resolution

The lock record slot for a resource is determined by:

```
slot = FNV-1a(resource_id) % 65536
```

The same FNV-1a hash function from the DLM lock table (`mxfsd_dlm.c`) is used. Hash collisions are resolved by linear probing — scanning forward through sequential slots until an empty slot is found or the record is located.

## Operations

### Lifecycle

- `mxfsd_disklock_init()` — Creates `.mxfs/` directory and `lockstate` file, pre-allocates with `fallocate()`, validates existing data.
- `mxfsd_disklock_shutdown()` — Stops heartbeat thread, closes the file descriptor.

### Lock Records

- `mxfsd_disklock_write_grant()` — Finds or allocates a slot for the resource, writes a GRANTED record. Called when a lock is granted.
- `mxfsd_disklock_clear_grant()` — Finds the record for a resource/owner and zeros the slot. Called when a lock is released.
- `mxfsd_disklock_read_all()` — Scans all 65536 lock slots, returns those with valid magic and active flags. Used during recovery for lock table reconstruction.
- `mxfsd_disklock_purge_node()` — Scans all slots, zeros those owned by the specified node. Also clears the node's heartbeat. Used during fencing.

### Heartbeat

- `mxfsd_disklock_write_heartbeat()` — Writes the local node's heartbeat record with current timestamp.
- `mxfsd_disklock_read_heartbeat()` — Reads any node's heartbeat record.
- `mxfsd_disklock_start_heartbeat()` — Starts a background thread that writes heartbeats every 2 seconds (MXFS_LEASE_RENEW_MS).
- `mxfsd_disklock_stop_heartbeat()` — Signals the thread to stop and joins it.

## Thread Safety

All operations are serialized via a `pthread_mutex_t` in the context structure. The heartbeat thread acquires this lock for each write. Multiple caller threads can safely invoke lock record operations concurrently.

## Performance

- **Hot path** (lock grant/release): One `pwrite()` of 512 bytes per operation.
- **Heartbeat**: One `pwrite()` every 2 seconds — negligible overhead.
- **Recovery** (`read_all`): Sequential scan of 65536 x 512 = 32 MB. Only done during master failover, not on the hot path.

## Constants

| Constant                      | Value     | Description                      |
|-------------------------------|-----------|----------------------------------|
| MXFS_DISKLOCK_RECORD_SIZE     | 512       | One sector per record            |
| MXFS_DISKLOCK_MAX_SLOTS       | 65536     | Max concurrent lock records      |
| MXFS_DISKLOCK_HB_SLOTS        | 64        | Max heartbeat slots (one/node)   |
| MXFS_DISKLOCK_MAGIC           | 0x4D584C4B| "MXLK" in ASCII                 |
| MXFS_DISKLOCK_HB_SIZE         | 32768     | Heartbeat region size in bytes   |
| MXFS_DISKLOCK_FILE_SIZE       | ~33 MB    | Total lockstate file size        |

## History

- v0.3.0: Initial implementation — full on-disk lock state persistence with heartbeat thread, O_DIRECT I/O, FNV-1a hashing with linear probing, sector-aligned atomic writes.
