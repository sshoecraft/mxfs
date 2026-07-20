# Journal Module (libmxfs/journal)

## Purpose
Write-ahead journal for metadata operations with crash recovery. Each node gets a dedicated circular buffer (slot) on the shared block device. Metadata changes are journaled before being applied, enabling recovery when a node dies. Also coordinates journal slot assignment and recovery across the cluster.

## Architecture
Three layers:
1. **Slot coordination** (original) — in-memory slot table tracking which node owns which slot, with state machine for recovery coordination
2. **Write engine** — circular buffer within each slot, transaction API for buffering and committing metadata writes
3. **Replay engine** — two-pass recovery: collect committed txn IDs + revoke set, then replay metadata entries

## On-Disk Layout

```
[journal_super 512B]                      <- offset
[slot0_hdr 512B] [slot0 data sectors...]  <- slot 0
[slot1_hdr 512B] [slot1 data sectors...]  <- slot 1
...
```

Each slot is a circular buffer of `slot_size_sectors` sectors (default 2048 = 1MB). Sector 0 of each slot is the slot header; sectors 1..N-1 are data. Head and tail track the write position and oldest valid entry.

### On-Disk Structures (all 512 bytes, native byte order)
- **mxfs_journal_super**: magic, version, slot_count, slot_size_sectors, sector_size, CRC, fs_uuid
- **mxfs_journal_slot_hdr**: magic, flags (CLEAN/DIRTY), owner, head_sector, tail_sector, seq_head, seq_tail, CRC
- **mxfs_journal_entry_hdr** (40 bytes): magic, type, seq, txn_id, total_len, payload_len, CRC — padded to 512B boundary

### Entry Types
- **METADATA** (1): disk_offset + data — replayed on recovery
- **REVOKE** (2): disk_offset + len — blocks replay of earlier writes to that offset
- **COMMIT** (3): marks a transaction as committed
- **CHECKPOINT** (4): advances tail, reclaims space
- **UNMOUNT** (5): clean shutdown marker, skips replay

## Transaction Model
```
txn = txn_begin()
txn_log_write(txn, offset, data, len)   // buffer metadata
txn_log_revoke(txn, offset, len)         // cancel prior writes
txn_commit(txn)                          // write all + COMMIT (no flush)
// or
txn_abort(txn)                           // discard everything
```

On commit: all buffered entries written to circular buffer, COMMIT entry appended. The device flush and slot header update are **deferred** — they happen when `mxfs_journal_flush()` is called from sync_fs, fsync, checkpoint, or unmount. This batches the expensive bdev_flush (~50ms on iSCSI) across many transactions instead of one per txn.

### Batched Commit Semantics
- `txn_commit()` writes journal entries + COMMIT entry to the circular buffer but does NOT issue a device flush or update the slot header. It increments `unflushed_commits`.
- `mxfs_journal_flush()` issues the device flush + slot header update and resets `unflushed_commits`. Called from `mxfs_sync_fs()`, `mxfs_fsync()`, `mxfs_journal_checkpoint()`, and `mxfs_journal_write_unmount()`.
- On crash, the last batch of unflushed commits may be lost. This is the same semantics as ext4's default 5-second commit interval.
- The safety guarantee: journal entries are sequentially written to disk by `write_entry()`. Even without an explicit flush, the device's write-back will eventually persist them. The flush just forces immediate durability.

## Recovery (Two-Pass Replay)
1. **Pass 1**: Scan tail..head collecting COMMIT entry txn_ids and REVOKE entries from committed txns
2. **Pass 2**: Scan again, replay METADATA entries from committed txns whose target offset is not in the revoke set
3. After replay: flush device, mark slot CLEAN

If an UNMOUNT entry is found, the slot was cleanly shut down and no replay is needed.

## Slot Coordination
- MXFS_MAX_NODES slot table with states: FREE, CLAIMED, ACTIVE, NEEDS_RECOVERY, RECOVERING, RECOVERED
- Claim: find first FREE slot, transition to ACTIVE
- Release: set local slot to FREE
- Recovery flow: ACTIVE -> NEEDS_RECOVERY -> RECOVERING -> FREE
- **On-disk fallback**: The in-memory slot table is per-node and only tracks locally claimed slots. For remote node recovery, `mark_needs_recovery()` and `find_slot_by_node()` fall back to scanning on-disk slot headers for DIRTY slots owned by the target node, then populate the in-memory entry.

## Key Design Decisions
- Native byte order for journal structures (same as disklock) — these are MXFS-internal, not XFS on-disk format
- 512-byte structs heap-allocated (not stack) to stay under kernel 1024-byte stack limit
- CRC32C on all on-disk structures for integrity verification
- Circular buffer wraps data sectors 1..N-1 (sector 0 is header)
- Slot header CRC mismatch on open treated as empty slot (reset head/tail)
- Auto-checkpoint on ENOSPC: when write_entry detects insufficient space, it checkpoints (advances tail to head) and retries before returning ENOSPC. Only returns ENOSPC if a single transaction exceeds the entire journal capacity.
- Proactive checkpoint at 75% full: write_entry triggers checkpoint when free sectors drop below 25% of capacity, preventing large transactions from hitting the wall
- Batched commits: txn_commit writes entries + COMMIT but defers the device flush and slot header update. The flush is batched and performed by mxfs_journal_flush() (called from sync_fs, fsync, checkpoint, unmount). Eliminates per-txn flush overhead (~50ms on iSCSI), reducing 1000-file create from ~50s to near-native speed.

## API

### Lifecycle
- `mxfs_journal_create(node_id)` / `mxfs_journal_destroy(ctx)`
- `mxfs_journal_format(dev, offset, slot_count, uuid)` — initialize fresh journal
- `mxfs_journal_open(ctx, dev, offset)` — read and validate journal super

### Slot Operations
- `mxfs_journal_claim_slot(ctx)` / `mxfs_journal_release_slot(ctx)`
- `mxfs_journal_slot_open(ctx, slot)` — load slot header, init write state
- `mxfs_journal_slot_mark_dirty(ctx)` / `mxfs_journal_slot_mark_clean(ctx)`

### Transactions
- `mxfs_journal_txn_begin(ctx)` -> `struct mxfs_txn *`
- `mxfs_journal_txn_log_write(ctx, txn, offset, data, len)`
- `mxfs_journal_txn_log_revoke(ctx, txn, offset, len)`
- `mxfs_journal_txn_commit(ctx, txn)` — writes entries + COMMIT to journal (flush deferred)
- `mxfs_journal_txn_abort(ctx, txn)` — discards buffered entries

### Recovery
- `mxfs_journal_replay(ctx, slot)` — two-pass replay
- `mxfs_journal_mark_needs_recovery(ctx, node_id)`
- `mxfs_journal_begin_recovery(ctx, slot)` / `mxfs_journal_finish_recovery(ctx, slot)`

### Maintenance
- `mxfs_journal_flush(ctx)` — flush unflushed commits to stable storage (bdev_flush + slot header)
- `mxfs_journal_checkpoint(ctx)` — advance tail, reclaim space
- `mxfs_journal_write_unmount(ctx)` — clean unmount marker

## Files
- journal.h: ~230 lines — on-disk structs, txn structs, context, full API
- journal.c: ~1500 lines — slot management + write engine + replay + transactions

## Ported From
kernel/mxfs_journal.{c,h} — kernel mutex replaced with PAL mutex, kernel types with stdint. Write engine, replay, and transaction API are new additions.

## History
- 2026-02-15: Ported from kernel to portable C using PAL (slot coordination only)
- 2026-02-19: Added journal write engine, circular buffer, transaction API, two-pass replay, checkpoint, unmount marker. All on-disk structures with CRC32C. Clean build on kernel 6.8.
- 2026-02-19: Added `bool slot_dirty` to `struct mxfs_journal_ctx`, set by `mxfs_journal_slot_open()` from the on-disk slot header flags. Enables mount code to detect if the previous shutdown was unclean and trigger replay.
- 2026-02-19: Wired into mount/unmount and inode flush (Phase 1 Steps 4-6). Mount: open/format/slot_open/replay/mark_dirty. Unmount: write_unmount/slot_mark_clean. Inode cache: txn_begin/log_write/commit before bdev_write in flush_inode_to_disk. Added `journal_offset` mount option (frontend + libmxfs).
- 2026-02-19: Phase 2 -- Multi-node recovery + full write coverage. Added `mxfs_journal_find_slot_by_node()` to look up a slot by node ID. Added compound transaction support via `compound_txn` field: when set, `txn_begin()` returns the compound txn, `txn_commit()`/`txn_abort()` are no-ops for sub-operations. Used by `mxfs_create()` for atomic create. Wired journal into alloc and dir_cache. Alloc: inode chunk writes journaled, block frees emit REVOKE. Dir cache: block and leaf dir writes journaled. Mount: `lease_expire_cb()` does full multi-node recovery (find slot, DLM EX lock on JOURNAL resource, begin/replay/finish).
- 2026-02-19: Fix ENOSPC when journal is full. Added `checkpoint_locked()` internal helper (advances tail to head without writing a CHECKPOINT entry, since journal may be out of space). Modified `write_entry()` to auto-checkpoint and retry when space is insufficient. Added proactive checkpoint at 75% capacity (free < 25% of data sectors). ENOSPC only returned when a single transaction exceeds the entire journal capacity.
- 2026-02-19: Fix dead-node journal recovery slot lookup failure. The in-memory `slots[]` table is per-node and has no knowledge of remote nodes' slot assignments. When a remote node crashed, `mark_needs_recovery()` and `find_slot_by_node()` returned -ENOENT because the dead node's slot was never in the surviving node's in-memory table. Fix: added `scan_disk_for_node_slot()` helper that reads on-disk slot headers to find DIRTY slots owned by a given node. Both `mark_needs_recovery()` and `find_slot_by_node()` now fall back to on-disk scan when the in-memory lookup fails, populating the in-memory slot entry from disk so the full recovery flow (begin_recovery, replay, finish_recovery) works correctly.
- 2026-02-19: Batched journal commits for metadata performance. `txn_commit()` no longer issues a `bdev_flush()` or updates the slot header per transaction. Instead, it writes journal entries + COMMIT entry and increments `unflushed_commits`. The device flush is batched and performed by the new `mxfs_journal_flush()` function, called from `mxfs_sync_fs()`, `mxfs_fsync()`, `mxfs_journal_checkpoint()`, and `mxfs_journal_write_unmount()`. All existing flush paths (checkpoint, checkpoint_locked, write_unmount) reset `unflushed_commits`. This eliminates per-txn flush overhead (~50ms on iSCSI), reducing 1000-file create from ~53s to near-native speed. No on-disk format changes. Crash semantics: last batch of unflushed commits may be lost (same as ext4's 5s commit interval).
- 2026-03-06: Added `xfs_dev` field to `struct mxfs_journal_ctx`. Journal replay now writes XFS metadata through `ctx->xfs_dev` (which has base_offset applied) instead of `ctx->dev`. This supports the new front-of-device layout where XFS data starts at a non-zero offset. Journal sector I/O (slot headers, entries) continues using `ctx->dev` with absolute offsets. Falls back to `ctx->dev` if `xfs_dev` is NULL (legacy layout).
- 2026-03-11: **Bug 122 fix -- removed compound_txn (v0.9.11).** Root cause: `compound_txn` was a global field on `struct mxfs_journal_ctx` shared by all threads. When concurrent create/mknod operations ran simultaneously, Thread A could pick up Thread B's compound_txn via `txn_begin()`, then Thread B would commit+free that txn while Thread A still held a pointer to it — use-after-free. Crash signature: `mxfs_journal_txn_log_write` dereferencing garbage `txn->tail` pointer (e.g., `0x75a73a8f13250e04`). Triggered by rsync (many concurrent file creates). Fix: removed compound_txn entirely from journal.h/journal.c and mount.c. Each sub-operation (inode flush, dir write, alloc) now creates its own independent transaction. Atomicity of create (alloc + init + dir_entry) is not needed — partial creates produce orphan inodes that are harmless and cleaned up by chk_mxfs. Files changed: journal.h, journal.c, mount.c.
