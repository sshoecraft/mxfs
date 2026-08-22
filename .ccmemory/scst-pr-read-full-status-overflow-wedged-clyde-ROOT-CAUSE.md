---
name: scst-pr-read-full-status-overflow-wedged-clyde-ROOT-CAUSE
description: ROOT CAUSE of the 2026-08-21 clyde host wedge: signed/unsigned compare in SCST scst_pr_read_full_status() overflows the cmd data buffer at >53 regist…
metadata:
  type: project
tags: [scst, clyde, host-wedge, rule2, persistent-reservations, memory-corruption, root-cause, fixed-and-verified]
---

## The bug (proven by code + deterministic reproduction)

`/src/scst/scst/src/scst_pres.c::scst_pr_read_full_status()`:

```c
int offset, size, size_max;                /* signed   */
const uint32_t rec_len = 24 + ts;          /* UNSIGNED  <-- the bug */
if (size_max - size > rec_len) { ...memcpy(&buffer[offset+24], reg->transport_id, ts)... }
size += rec_len;                           /* counts SKIPPED registrants too */
```

`size` accumulates every registrant including skipped ones. The first one that
does not fit pushes `size` past `size_max`; the difference goes negative; the
comparison is promoted to UNSIGNED because `rec_len` is `uint32_t`; ~4e9 > rec_len
is true; **every remaining registrant is memcpy'd past the end of the command's
data buffer.**

`scst_pr_read_keys()` immediately above is SAFE — its literal `8` keeps the
comparison signed. The whole difference is the type of one local.

## Why the rig reached it

MXFS probes with a 4096-byte buffer and resizes on the reported ADDITIONAL
LENGTH (`pal/linux/kern.c:3813 mxfs_pal_scsi_pr_read_full_status`) — correct,
standard SPC behaviour. The bug arms whenever the registrant list outgrows the
probe buffer: ~53 iSCSI registrants. **32 nodes x 2 mpath paths = 64.** The rig
crossed the threshold when it scaled to 32 nodes; nothing about MXFS is wrong.

## The kill chain (2026-08-21, journal boot -1)

- 08:25:22 / 08:52:58 / 09:03:00 — `scst_set_resp_data_len ***ERROR***: Too big
  response data len 4496 / 4848 / 5024 (max 4096)`, stack naming
  `scst_pr_read_full_status`. Growing with the registrant list. SCST's own
  comment there: "It's a bug in the lower level code".
- 09:05:24 — `BUG: Bad page map in process CPU 1/KVM pte:66786d2d36317473` and
  `pte:692c65646f6e2d73`. Those PTEs are little-endian ASCII "st16-mxf" and
  "s-node,i" — consecutive 8-byte chunks of `...test16-mxfs-node,i,0x...`, an
  iSCSI TransportID. A register in the oops held ASCII "3d0200" (ISID hex).
  A live QEMU page-table page was full of the exact payload of that memcpy.
- Oops in `vm_normal_folio` <- `change_prot_numa` <- `task_numa_work`; the vCPU
  thread exited **with irqs disabled, preempt_count 1**; `migration/49` then
  stuck >387s in `multi_cpu_stop` (stop_machine never completes) -> RCU stalls
  -> 23 threads in synchronize_rcu -> jbd2 in `__wait_on_buffer` with the nvme
  IDLE -> journald unkillable. Manual reset required.

## The fix — +caw-abort-reclaim.4 (built, installed, verified)

- Bound taken against `offset` (bytes actually written), signed types, clamped
  to `min(buffer_size, cmd->bufflen)`; stop at the first descriptor that does
  not fit; ADDITIONAL LENGTH still reports the FULL length so the initiator can
  resize. Also hardened two wrap-prone wire-length guards in the same file
  (`ext_size + 28` at ~1234, `tid_buffer_size + 24` at ~1759).
- **iscsi-scst MUST be rebuilt too**: SCST_INTERFACE_VERSION = SCST_VERSION_STRING
  + SCST_INTF_VER, so a stale iscsi-scst.ko is refused at target-template
  registration and the target silently will not come up.

## Verification

`tests/scst_pr_bounds_check.sh` (+ `tests/scst_pr_fullstatus_bounds.c`): runs
both loop variants against a PROT_NONE guard page in a forked child.
Measured: OLD dies of SIGSEGV at 64 registrants / 4096 bytes; NEW stops at
offset 4056 and still reports addl=5632. Also asserts the INSTALLED scst.ko is
.4+ and that iscsi-scst matches. gcc's own `-Wsign-compare` flags the old form.

**NEVER reproduce this against an unpatched module** — the "before" arm is the
historical evidence above. Re-running the overflow corrupts host memory.

## Not specific to this fork

The overflow is in SCST's own PR handler, reachable by any initiator that
probes READ FULL STATUS with a short buffer against a many-registrant target.
Worth upstreaming.
