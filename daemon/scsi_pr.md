# SCSI-3 Persistent Reservations Module

## Overview

`mxfsd_scsi_pr` provides hardware-level I/O fencing for MXFS using SCSI-3 Persistent Reservations (PR). When a node is declared dead by the cluster, its SCSI registration key is preempted on the shared storage device, causing the storage target to reject all further I/O from that node. This prevents a partitioned or zombie node from corrupting the filesystem.

## Files

- `daemon/mxfsd_scsi_pr.h` — public interface
- `daemon/mxfsd_scsi_pr.c` — implementation

## Architecture

### SG_IO Interface

All SCSI commands are issued via the Linux `SG_IO` ioctl (v3 interface, `struct sg_io_hdr`). The device is opened `O_RDWR` and the file descriptor is held for the lifetime of the context.

### SCSI Commands Used

**PERSISTENT RESERVE OUT** (opcode `0x5F`):
- CDB: 10 bytes. Byte 1 = service action, byte 2 = scope/type, bytes 7-8 = parameter data length.
- Parameter data: 24 bytes. Bytes 0-7 = reservation key, bytes 8-15 = service action reservation key.
- Service actions:
  - `REGISTER` (0x00) — register or unregister a key (must provide current key)
  - `RESERVE` (0x01) — acquire a reservation
  - `RELEASE` (0x02) — release a reservation
  - `PREEMPT` (0x04) — preempt another node's key (fencing)
  - `REGISTER_AND_IGNORE` (0x06) — register ignoring current key state (used for initial setup and daemon restarts)

**PERSISTENT RESERVE IN** (opcode `0x5E`):
- CDB: 10 bytes. Byte 1 = service action, bytes 7-8 = allocation length.
- Service actions:
  - `READ_KEYS` (0x00) — returns all registered keys
  - `READ_RESERVATION` (0x01) — returns the current reservation holder

### Reservation Type

Type 5: **WRITE EXCLUSIVE - REGISTRANTS ONLY**. All nodes with a registered key can perform both read and write I/O. Nodes without a registration are blocked from all write I/O by the storage target hardware.

### Registration Keys

Each node's key is simply `(uint64_t)node_id`. This makes it trivial to determine which node owns which key when reading the key list from the device.

### Fencing Flow

1. On startup, each node calls `mxfsd_scsi_pr_register()` to place its key on the device using `REGISTER_AND_IGNORE`. This is idempotent and works even if a stale key from a previous daemon instance exists.
2. One node calls `mxfsd_scsi_pr_reserve()` to establish the WRITE EXCLUSIVE - REGISTRANTS ONLY reservation.
3. When a node is declared dead, a surviving node calls `mxfsd_scsi_pr_preempt(victim_key)`. This atomically removes the victim's registration and transfers the reservation to the preempting node.
4. The fenced node can no longer perform I/O to the device. If it recovers, it must re-register before resuming.
5. On clean shutdown, `mxfsd_scsi_pr_unregister()` removes the node's key using `REGISTER` with `sa_key=0`.

### Error Handling

- Transport errors checked via `host_status` and `driver_status`
- SCSI status `0x18` (RESERVATION CONFLICT) returns `-EBUSY`
- CHECK CONDITION (status `0x02`) triggers sense data parsing: sense key, ASC, and ASCQ are decoded and logged
- All errors are logged at `LOG_ERR` level

### Thread Safety

All operations acquire `ctx->lock` (pthread mutex) before issuing SCSI commands. This prevents concurrent SG_IO calls on the same fd, which is required for correct operation.

## API

```c
/* Initialize context, open device */
int  mxfsd_scsi_pr_init(ctx, device, key);

/* Clean shutdown, close device */
void mxfsd_scsi_pr_shutdown(ctx);

/* Register key with device (idempotent) */
int  mxfsd_scsi_pr_register(ctx);

/* Acquire WR_EX_REG_ONLY reservation */
int  mxfsd_scsi_pr_reserve(ctx);

/* Preempt a dead node's key */
int  mxfsd_scsi_pr_preempt(ctx, victim_key);

/* Read all registered keys */
int  mxfsd_scsi_pr_read_keys(ctx, keys, count, max);

/* Read current reservation */
int  mxfsd_scsi_pr_read_reservation(ctx, key, type);

/* Unregister key on clean shutdown */
int  mxfsd_scsi_pr_unregister(ctx);
```

All functions return 0 on success, negative errno on failure.

## Dependencies

- Linux SG_IO v3 (`<scsi/sg.h>`, `<scsi/scsi.h>`)
- Device must support SCSI-3 Persistent Reservations (shared SAN LUNs, most iSCSI targets)
- Device must be opened `O_RDWR`

## History

- v0.3.0: Initial implementation (2026-02-11)
