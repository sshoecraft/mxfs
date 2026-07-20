---
name: sess43-killing-drc-cap2-midflight-leaks-module-refcount
description: OPERATIONAL: TaskStop-ing drc_cap2/run.sh mid-flight leaks mxfs module refcount=1 (no holders/mounts) → rmmod fails → mkfs prep fails. Fix: virsh des…
metadata:
  type: reference
---

## sess43 operational lesson — don't kill drc_cap2 mid-flight; if you do, reboot the VMs

Killing the drc_cap2 / `run.sh 2 tcp` background task with TaskStop while it is MID-TEST (nodes actively creating files) leaves a leaked in-kernel reference: `rmmod mxfs` → "Module mxfs is in use", `/sys/module/mxfs/refcnt`=1 with EMPTY holders and NO mounts (the DLM/peer thread or workqueue didn't clean up on the abrupt kill). The next `run.sh` prep then fails at `mkfs_mxfs -f /dev/sda returned 1` (device/module busy) → "PREP FAIL (mkfs)" → ABORT.

### RECOVERY (clean slate): reboot the test VMs (allowed — RULE 2 forbids only the HOST clyde):
```
virsh -c qemu:///system destroy test1; virsh -c qemu:///system destroy test2
virsh -c qemu:///system start test1;   virsh -c qemu:///system start test2
# wait for ssh (test1 ~4s, test2 ~12s), then verify: lsmod|grep mxfs == empty, /src/mxfs/mxfs.ko visible (NFS auto-remounts)
```
After reboot: mxfs_loaded=0, NFS auto-mounted, fresh mxfs.ko visible — prep succeeds.

### PREVENTION: let drc_cap2 run to completion (it has its own timeout 450 + cleanup that kills streamers + node-side followers). If you must stop early, expect the refcount leak and budget a VM reboot. Passing MXFS_EXTRA_MODARGS to drc_cap2 works (exported → run.sh → prep_node.sh): e.g. `MXFS_EXTRA_MODARGS="dir_force_block=1" bash tests/drc_cap2.sh`.
</body>
