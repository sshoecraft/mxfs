# The slice lifecycle record

What it is: one 512-byte record per XFS log slice, in its own envelope
region (`MXFS_FORMAT_F_SLIFE`, `slife_offset`/`slife_size` in the envelope
super, 32 KiB after the bootstrap region), that says whether the slice's
payload may be trusted to be zero.  Three states:

| state | meaning |
|---|---|
| `INIT_REQUIRED` | mkfs wrote it.  The payload is whatever the format's userspace write left, which is not known to be on the platter. |
| `ZEROING` | a claimant persisted this and started the FUA zero, and has not persisted `READY`.  A crash here, or a target that refused to persist the zero, leaves it. |
| `READY` | the payload was zeroed through the kernel FUA path, flushed, read back in full, and only then was this state persisted.  Sticky for the filesystem incarnation. |

The record binds the state to the filesystem's uuid, the slice index, a
generation (bumped at every `INIT_REQUIRED`/`ZEROING` to `READY`), the
claimant's node and incarnation epoch, and a CRC32C.

## Why it exists

Head discovery in log recovery is cycle-number based: `xlog_find_head` and
`xlog_find_zeroed` read cycle stamps from data blocks and choose branches
before any record's uuid is checked, and per-record validation runs only on
the head they pick.  A slice whose never-written blocks still hold a
previous incarnation's CRC-valid records therefore mis-steers discovery: the
first mount is clean (block 0 zero reads as a totally zeroed log), the
incarnation journals normally, and after a crash discovery lands on a stale
header, the slice is refused, and every committed transaction in it is
unrecoverable.  Measured on the two-node TCP rig (s60j, 0.87.23): 0 of 40
log-forced files back, the node unable to mount, against the control's 40
of 40.

mkfs cannot promise the zero.  Its write goes through a userspace path
whose durability the target stack does not guarantee (the long-standing
note about `pwrite`+`O_SYNC` on the LIO/SCST stack), and there is no way to
tell a slice whose zero landed from one whose zero did not by looking at
the payload — that is the whole problem.

A recovery-side answer was considered and rejected in design consult (the
ruling is in `rulings/twin-hole-fix-zeroing-strictness.md`): serving every
block no current-uuid record header covers as zero.  After a wrap, an
obsolete record's body blocks can lose their header to a later, shorter
record while their cycle stamps remain exactly what discovery reads; masked
to zero, a dirty log reads as totally zeroed and required replay is skipped
silently, which is worse than the refusal.  Removing information from
recovery's input has the same data-loss consequence as removing it from the
disk.

## The invariants

1. **Nothing is journaled into a slice before its `READY` is durable.**  The
   claim happens after the heartbeat slot claim (the slot is the exclusive
   lease on the identically numbered slice) and before `xfs_mountfs` mounts
   the log.  `READY` is written FUA and read back before the claim returns.
2. **The zero is proven, not assumed.**  `ZEROING` is persisted FUA first;
   the payload is zeroed with FUA writes; the device is flushed; every byte
   is read back through the FUA read path and compared against zero; then
   `READY`.  A write that returned success is not evidence the bytes are on
   the platter.
3. **A crash in `ZEROING` restarts the whole zero.**  There is no progress
   metadata to trust.  The next claimant of the slot does it again.
4. **Nothing infers a slice is safe to zero.**  Not "no live head", not node
   identity, not adoption, not log content.  A record that is missing (zero
   sector), malformed, out of state range, or another volume's refuses the
   mount of that slot.  A volume formatted without the region keeps the old
   behaviour and says so at every claim; `INIT_REQUIRED` is never
   synthesised for a slice that may have been used.
5. **A foreign recovery of a slice not `READY` replays nothing.**  By (1) no
   record of this incarnation can be in it, and its payload is exactly the
   bytes discovery must be kept away from.  The record is left as it is for
   the slot's next claimant.  A record that cannot be read or validated is a
   retryable error, never a replay.
6. **The region is a format decision, protocol-gated.**  Generation 20: a
   node that does not consult the record would journal into an untrusted
   payload, and a consulting node's foreign recovery of that slice would
   then skip records that exist.  Only mkfs lays the region out; the
   offline upgrade refuses a volume without it.

## I/O shape

The zero and the readback run in 64 KiB chunks of physically contiguous
memory.  The readback is a SCSI READ(16) passthrough (the same primitive
the heartbeat reads use), which the block layer refuses above the LUN's
hardware transfer limit (512 KiB on the two-node rig's LUN) and which maps
the buffer's pages by virtual address, so the buffer must not be vmalloc
memory.  A 64 MiB slice is 1024 FUA writes and 1024 FUA reads, once per
slice per filesystem incarnation; the claim line reports `zero_ms`.

## Where it lives

- On-disk definitions: `include/mxfs/mxfs_super.h` (`struct mxfs_slife_record`, states, `MXFS_SLIFE_BYTES`).
- Reader and claimant state machine: `dlm/bootstrap.c` (`mxfs_slife_read`, `mxfs_slife_claim_init`).
- DLM plumbing: `dlm/v5_mount.c` (`mxfs_v5_dlm_slice_lifecycle_claim`, `..._state`).
- The claim at mount: `pal/linux/xfs_super.c`, after the slot claim, before `xfs_mountfs` (`P-SLIFE`, `P-SLIFE-REFUSED`, `P-SLIFE-LEGACY`).
- The foreign-recovery skip: `xfs/xfs_log.c` (`P-SLIFE-FOREIGN-UNINIT`, `P-SLIFE-FOREIGN-UNREADABLE`).
- Format and check: `tools/mkfs_mxfs.c` (records written after the native format settles the slice count), `tools/chk_mxfs.c` (`check_slife`).
- The measurement: `tests/d0531_stale_slice_recovery.sh` (plant proven present before the claim, gone at the crash, lifecycle line at the first mount).

## Open

The per-record incarnation stamp (ruling item (c)) is still the completion
of this design: it covers rollback, cloning, an initialisation bug and stale
media, none of which a zeroed payload alone can distinguish from a genuine
record of this incarnation.
