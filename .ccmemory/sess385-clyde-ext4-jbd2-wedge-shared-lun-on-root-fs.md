---
name: sess385-clyde-ext4-jbd2-wedge-shared-lun-on-root-fs
description: The shared LUN /home/steve/disk.img AND all 32 guest qcow2 images sit on clyde's ONE 92%-full ext4; probe/log volume deadlocked jbd2 and wedged the h…
metadata:
  type: reference
tags: [rig, clyde, rule2, rule2c, scst, ext4, infra, instrumentation]
---

## The structural fact nobody had written down

    /sys/kernel/scst_tgt/devices/mxfs/filename = /home/steve/disk.img   (o_direct=1)
    guest root disks                           = /home/steve/vms/qemu/testN/testN (qcow2)
    both                                       = /dev/nvme0n1p2, ext4, 1.8T, 92% FULL

**The shared LUN under test and all 32 guests' root disks are files on the SAME
ext4 filesystem on clyde, and it is 92% full.** One jbd2 journal serializes
metadata for all of it. That coupling is invisible until it bites.

## How it bit (sess385, 2026-08-20)

Symptom order:
1. 12 of 32 guests stopped answering ssh while still answering **ping** —
   network stack fine, session setup blocked.
2. Their serial logs showed `jbd2/dm-0-8`, `systemd-journal`, `dmesg`, `cron`
   blocked >60s. **dm-0 is the guest ROOT ext4, not mxfs (dm-1)** — so this is
   not an MXFS fault, and reading it as one wastes a session.
3. `virsh destroy` on all 12: every one timed out at 40s.
4. On clyde: **875 D-state threads** — 813 qemu `worker` (63 per qemu) plus 47
   `iscsi_conn_cleanup`; loadavg 870 and climbing; **nvme 1.6% busy, 270 KB/s**;
   MemAvailable 39 GB, Dirty 920 kB.

Idle disk + free memory + hundreds of blocked threads = **lock deadlock, not
slowness.** The stacks name it:

    ext4_buffered_write_iter <- ext4_file_write_iter <- vfs_write   <- __x64_sys_pwrite64
    ext4_buffered_write_iter <- ext4_file_write_iter <- vfs_writev  <- __x64_sys_pwritev
    jbd2_log_wait_commit <- jbd2_complete_transaction <- ext4_fc_commit <- ext4_sync_file   <- fdatasync
    jbd2_log_wait_commit <- __jbd2_journal_force_commit <- ext4_force_commit <- ext4_sync_file

`jbd2_log_wait_commit` is the head of the chain; the qemu workers are queued
behind the journal commit. SCST meanwhile logged `NEXUS_LOSS_SESS` TM functions
from initiator after initiator as guest iSCSI sessions timed out.

## What tipped it over — my own instrumentation

`P85-INODE-DRAIN-CENSUS` printed one line per AG release. At 32 nodes that is
~1000 lines/node/chunk; each guest's systemd-journal writes them to its root
ext4 -> virtio-blk -> a qemu worker `pwrite` into the qcow2 on clyde's ext4.
Thirty-two of those against a 92%-full ext4 stalled the journal.

**Instrumentation that cannot be left on is not instrumentation.** Both probes
are now anomaly-only: P85 prints only on `werr/ferr/nohold/allocq/passes>0`, and
P86 keeps its per-bad-head warning but emits totals at most once per 30 s.

This is the same host failure sess384 hit on test4
(`libvirt-domain-deadlock-recovery-without-host-reset`) — qemu threads
unkillable in `ext4_buffered_write_iter` — but fleet-wide instead of one domain.

## Rules that apply

- **RULE 2: never reboot clyde.** Document and report; the reset is the user's call.
- **RULE 2c:** `virsh destroy` against a deadlocked domain hangs — always bound it
  with `timeout`, never retry blindly, and never reach for `dmsetup`/`umount`.
- `tools/recover_wedged_domain.sh` fixes ONE domain but copies its ~26 GB image.
  **It does not scale to 12 domains** — that is ~312 GB against 151 GB free. Do
  not start it in a loop.

## Triage tool

`sudo tools/clyde_wedge_diag.sh` (added sess385). RULE-2c-safe: reads only
`/proc/<pid>/stat`, `comm`, `task/*/stat`, `task/*/stack`; never `cmdline`,
never `maps`, never `pgrep -f`. Prints loadavg, memory, a 10-second nvme delta,
D-threads by comm and by owning process, sampled stack signatures, SCST device
state and TM traffic, and ext4 fill. It only reports — it never acts.

## The standing fix for the rig

Move the shared LUN off the root filesystem (its own device/partition), or free
clyde's root below ~80%. Until then, treat guest kernel-log volume as a rig
resource: any probe on a per-AG-release or per-buffer path must be anomaly-gated
before it runs at 32 nodes.
