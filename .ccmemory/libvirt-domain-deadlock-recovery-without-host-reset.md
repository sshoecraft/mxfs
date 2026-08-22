---
name: libvirt-domain-deadlock-recovery-without-host-reset
description: One wedged qemu deadlocks libvirtd for THAT domain and hangs `virsh list --all`; tools/recover_wedged_domain.sh clears it in ~3min with no host reset.
metadata:
  type: reference
tags: [rig, libvirt, rule2, rule2c, clyde, recovery]
---

## Symptom (measured on clyde 2026-08-20, sess384, domain test4)

    virsh destroy test4
      error: Failed to terminate process 1188423 with SIGKILL: Device or resource busy
    virsh domstate test4    -> NEVER RETURNS
    virsh domstate test5    -> answers instantly
    virsh list --all        -> hangs (it touches every domain)

libvirtd itself is fine (`S`, in `poll`); it is deadlocked on ONE domain object.

The qemu leader is a **zombie with live sub-threads in uninterruptible sleep**.
All five were here:

    ext4_buffered_write_iter+0x39 -> ext4_file_write_iter -> vfs_writev
      -> __x64_sys_pwritev

i.e. blocked writing the guest's SERIAL LOG on the HOST's own ext4. MXFS is not
in that path at all — do not read it as a filesystem defect. A D-state task
cannot take a signal, so libvirtd retries the kill forever.

Diagnose it safely (RULE 2c): `/proc/<pid>/stat`, `/proc/<pid>/task/*/stat` and
`/proc/<pid>/task/*/stack` are safe on a wedged host; `cmdline` and `maps` are
not, and `pgrep -f` is banned. `tools/mxfs_pgrep.sh` is the safe matcher.

## What blocks a restart, in the order each becomes visible

Each one only surfaces after the previous is cleared — this is why it looks
unrecoverable if you stop at the first error:

1. libvirtd's runtime state — `/run/libvirt/qemu/<d>.{pid,xml}`
2. virtlogd's lock on the SERIAL log — `Cannot open log file:
   '/var/log/libvirt/qemu/<d>-serial.log': Device or resource busy`.
   The lock is keyed by PATH and survives a rename, so the persistent XML must
   be repointed at a different filename, not just moved aside.
3. virtlogd's lock on the QEMU log — `<d>.log`, same shape
4. virtlockd's lease on the DISK IMAGE — `unable to lock <img> for metadata
   change: Resource temporarily unavailable`. **Unbreakable** while the zombie
   holds the fd: the domain must be pointed at a COPY.
5. systemd-machined's stale registration — `GDBus.Error:
   org.freedesktop.machine1.MachineExists: Machine 'qemu-<id>-<d>' already
   exists`. Clear with `machinectl terminate qemu-<id>-<d>`.

## Recovery — `sudo tools/recover_wedged_domain.sh <domain>`

Automates all five. ~3 minutes, dominated by the image copy (26 GB in 75s;
`cp --sparse=always`). Verified end to end: test4 came back and the 32-node
cluster re-prepped clean (60s, all 32 `active_count=32`).

It restarts libvirtd and virtlogd — running guests survive both. It NEVER
reboots or sysrqs the host (RULE 2). The old image is left in place because the
stuck threads still hold it; only a host reset clears that process.

After the domain starts it has **no /src** (NFS is deliberately not an fstab
automount, see `feedback-src-nfs-not-fstab-automount`) — mount it before the
node can run anything from the tree.

## The harness hazard this created

`run.sh`'s `power_cycle_node()` called `virsh destroy`/`start` UNBOUNDED. Against
a deadlocked domain that hangs `prep_cluster` forever in an unattended ccloop
run — the exact RULE 2b/2c failure shape. Every `virsh` call in `run.sh` is now
`timeout 60` with a WARN on expiry. **Never add an unbounded `virsh` call.**

## Also worth knowing

A guest whose libvirt domain cannot be power-cycled will still answer ssh and
will still be *mounted* — so `prep_cluster` re-mkfs'd the LUN under it and it
correctly self-fenced with `P131-SELF-FENCE ... device reformatted under live
mount (super fs_uuid mismatch)`. The visible symptom was prep failing its
convergence gate at `active_count=30` twice in a row. Two nodes stuck at an old
uptime while everything else shows a fresh one is the giveaway.
