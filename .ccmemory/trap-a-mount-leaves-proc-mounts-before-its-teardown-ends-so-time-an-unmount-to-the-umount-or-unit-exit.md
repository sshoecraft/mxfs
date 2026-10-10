---
name: trap-a-mount-leaves-proc-mounts-before-its-teardown-ends-so-time-an-unmount-to-the-umount-or-unit-exit
description: TRAP: umount(2) detaches the mount from /proc/mounts at once; put_super (MXFS ledger handoff) runs on 30-60 s. Time unmounts to umount/unit exit.
metadata:
  type: feedback
tags: [trap, harness, unmount, pve, dyndbg]
---

An MXFS mount disappears from /proc/mounts as soon as umount(2) detaches it. The superblock teardown (put_super: grant release, ledger page handoff to the survivor, GOODBYE) runs after that, in the umount task's final mntput, and the umount command does not return until it ends.

Measured on the physical DRBD pair (tests/pve_depart_wall.sh, 0.90.108): polling `grep ' /mnt/shared mxfs ' /proc/mounts` reported the departure done at 0.7-0.8 s. The DLM actually shut down 31 s and 61 s later. The harness also switched the dyndbg probes off at the "done" mark, so every handoff probe after 0.8 s was lost and P-TAUTH-DEPART never printed ("no P-TAUTH-DEPART line" looked like "nothing to hand off").

How to apply:
- Time an unmount to the `umount` process exiting, or for the mxfs-drbd@ unit to `systemctl is-active` leaving active/deactivating (inactive = clean, failed = it overran).
- Cross-check the kernel's own marks: `mxfs: DLM shutting down` → `P-RELALL-WALL` → `P-TAUTH-DEPART ... ms=` → `mxfs: DLM shutdown complete`.
- Keep probes on until the unit has stopped.

Related: dyndbg `format "%s%pV"` enables only mxfs_pal_log sites; a plain pr_debug probe such as P-DRBD-CAS-STATS needs its own `format "P-DRBD-CAS-STATS" +p`.
