---
name: reference-there-is-no-in-kernel-scsi-task-management-path-for-an-out-of-tree-module-on-6-8
description: REFERENCE (s83, 6.8.0-101): scsi_ioctl_reset is global but UNEXPORTED and takes int __user *; the try_*_reset helpers are static — a module cannot is…
metadata:
  type: reference
tags: [scsi, kernel-api, fencing, lu-reset]
---

# A kernel module cannot issue a SCSI task-management function

Established by reading the deployed kernel (6.8.0-101-generic on test1/test2,
source at /src/linux), session 83. Do not re-derive it; re-check it only when
the fleet's kernel changes.

| symbol | where | status |
|---|---|---|
| `scsi_ioctl` | drivers/scsi/scsi_ioctl.c:960 | `EXPORT_SYMBOL` — linkable, but its `SG_SCSI_RESET` case takes `void __user *` |
| `scsi_ioctl_reset` | drivers/scsi/scsi_error.c:2495, declared in include/scsi/scsi_eh.h | **global (`T` in /proc/kallsyms) but NO `EXPORT_SYMBOL`** — absent from Module.symvers, so modpost rejects it. And it does `get_user(val, arg)` on an `int __user *` |
| `scsi_try_bus_device_reset` | scsi_error.c:1008 | `static` |
| `scsi_try_target_reset` | scsi_error.c:977 | `static` (`t` in kallsyms) |
| `scsi_execute_cmd` | | `EXPORT_SYMBOL` — ordinary CDBs only; a TMF is not a CDB |

So there are exactly three shapes, and two are forbidden:

- **A kernel patch adding a supported task-management interface** with real
  completion provenance. This is the ruled preference; a product-level kernel
  dependency is an acceptable cost for an integrity-critical fencing primitive.
  Exporting `scsi_try_bus_device_reset()` alone is not enough — the interface
  must own references, serialisation, queue/recovery coordination, completion
  lifetime and the transport evidence.
- **A privileged userspace helper** doing the `SG_SCSI_RESET_DEVICE |
  SG_SCSI_RESET_NO_ESCALATE` ioctl. Admissible in principle, but only with a
  real invocation/incarnation binding — an exit status plus a `tmfrsp_pdus`
  delta is not one, since a counter can move for another TMF and a session can
  recover between two observations. A helper whose executable or control path
  depends on the filesystem being recovered is a deadlock.
- **Forbidden**: passing a kernel pointer as the ioctl's user pointer;
  resolving the unexported symbol by address (kprobe/kallsyms); fabricating a
  `scsi_cmnd` and calling the host template's `eh_device_reset_handler` (its
  locking, recovery state, queue handling and calling-context assumptions
  matter).

**What the ioctl means on this stack**, read from the same source and worth
keeping: `scsi_ioctl_reset()` maps `SG_SCSI_RESET_DEVICE|NO_ESCALATE` to
exactly `scsi_try_bus_device_reset()` with no fallthrough, returning 0 only for
`SUCCESS`; `iscsi_eh_device_reset()` returns SUCCESS only when
`session->tmf_state == TMF_SUCCESS`, which `iscsi_tmf_rsp()` sets only on
`ISCSI_TMF_RSP_COMPLETE` in the target's own TMF response PDU; a timeout
returns FAILED through `iscsi_conn_failure()` and a session that is not
LOGGED_IN returns FAILED without sending anything. So on iscsi_tcp the
"local teardown wearing a witness's clothes" ambiguity does not exist — but the
same handler then calls `fail_scsi_tasks(conn, lun, DID_ERROR)`, which is why
the issuer survives and a bystander does not.
