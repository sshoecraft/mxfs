# SCSI PR Module (libmxfs/scsipr)

## Purpose
Hardware-level I/O fencing using SCSI-3 Persistent Reservations. Ensures only registered cluster nodes can perform I/O to the shared block device.

## Architecture
Thin wrapper around PAL SCSI PR functions. Manages per-mount context (device handle, local key, reservation state). Uses WRITE EXCLUSIVE - REGISTRANTS ONLY (type 5) so all registered nodes share access.

## Ported From
kernel/mxfs_scsipr.{c,h} — kernel pr_ops replaced with PAL SCSI PR API.

## Key Design
- `mxfs_scsipr_ctx` holds device handle, key (node_id), reserved flag
- Register: idempotent via REGISTER_AND_IGNORE semantics
- Reserve: type 5, tolerates -EBUSY (another node holds reservation)
- Preempt: atomically removes victim key, takes reservation
- Unregister: clean shutdown removes key
- Gracefully handles -EOPNOTSUPP (platform lacks SCSI PR)

## Files
- scsipr.h: 51 lines — context struct, public API
- scsipr.c: 193 lines — implementation

## History
- 2026-02-15: Ported from kernel to portable C using PAL
