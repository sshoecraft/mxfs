---
name: rig-recovery-after-clyde-reboot-scst-mpath
description: 32-node CAW rig recovery after a clyde reboot: scst.service is a RED HERRING (stale /etc/scst.conf) — use scst_setup.sh + mpath_up.sh, not systemctl.
metadata:
  type: reference
tags: [rig, infra, scst, multipath, clyde, recovery]
---

# Recovering the 32-node CAW rig after a clyde reboot

## Symptom

`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` power-cycles ALL 32 nodes and
ends with:

    WARN: testN booted but /dev/mapper/mpatha never appeared      (x32)
    PREP FAIL: unusable after power cycle: test1 ... test32

or, once nodes are reachable, `FS_PREP_FAIL: /dev/mapper/mpatha is not a block device`.

**This is host-side, not a node fault and not an MXFS fault.** Do not diagnose the
filesystem from it, and do not let the mass power-cycle mislead you.

## Diagnosis (30 seconds)

    uptime                                   # recent boot?
    ls /sys/kernel/scst_tgt/targets/iscsi/   # missing => SCST not loaded
    systemctl status scst                    # may say "failed"

## THE TRAP — scst.service is not the rig

`/etc/scst.conf` is a stale SCST-Configurator artifact naming
`/home/steve/disk-1.img` and `/home/steve/disk-2.img`, both long deleted. The unit
therefore fails at boot with, in dmesg:

    dev_vdisk: vdisk_get_file_size: ***ERROR***: opening /home/steve/disk-1.img failed: -2
    scst: scst_assign_dev_handler: New device handler's vdisk_fileio attach() failed: -2

**Do not try to fix scst.service or recreate disk-1.img.** The 32-node CAW rig does
not use the systemd unit at all; it uses `scripts/scst_setup.sh`, whose device is
`/home/steve/disk.img` (50G, holds the live MXFS envelope — magic `MXFS` at byte 0).

## The actual recovery

    sudo bash scripts/scst_setup.sh setup      # vdisk_fileio "mxfs" -> iqn...:shared
    sudo -E bash scripts/mpath_up.sh up 32     # 2nd portal .2 on br0 + 32 guest logins
    MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster

Timings measured 2026-08-03: scst_setup ~2s, mpath_up 32/32 ~100s, prep 76s.
`mpath_up.sh up` is idempotent and doubles as the readiness gate (it prints
`MPATH_OK 2` per node — 2 paths, portals 192.168.120.1 + .2).

## Why mpath

The 32/caw board is **condition 4** (`scripts/rig.sh` header): CAW over
dm-multipath, `MXFS_DEV=/dev/mapper/mpatha`. `scst_setup.sh` alone pins the target
to portal .1 only (condition 3, direct) — `mpath_up.sh` re-runs setup with both
portals. So run mpath_up even if scst_setup already succeeded.

Related: [[env-cluster-bringup-after-host-reboot]] (the older 2-node LIO/TCP rig —
different stack: LIO tcm_loop + /dev/mxfs-shared; CAW needs SCST).
