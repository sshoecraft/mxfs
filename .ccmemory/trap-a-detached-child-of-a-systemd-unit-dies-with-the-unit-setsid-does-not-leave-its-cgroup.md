---
name: trap-a-detached-child-of-a-systemd-unit-dies-with-the-unit-setsid-does-not-leave-its-cgroup
description: TRAP (0.90.72→73): restart_host() Popen(start_new_session=True) a 'sleep 10; sysrq b' from a systemd-run unit; the unit's exit killed it. Do it in-pr…
metadata:
  type: feedback
---

A process started from inside a systemd service (including a `systemd-run` transient unit) stays in that unit's cgroup however it is detached: `setsid`, `start_new_session=True`, `nohup`, double fork. When the unit's main process exits, systemd stops the unit and, with the default `KillMode=control-group`, kills every process left in the cgroup.

**What bit us:** `tools/mxfs_drbd_fence_self.py restart_host()` Popen'd `sh -c 'sleep 10; echo b > /proc/sysrq-trigger'` with `start_new_session=True` from the guard's rejoin unit `mxfs-drbd-rejoin-<res>`, then returned. pve2 logged "restarting this host in 10 s" three times and never restarted (2026-10-06, defect D-DRBD-REJOIN-HOST-RESTART-FALLBACK-DIES-WITH-ITS-UNIT).

**Measured on pve9-1 (PVE 9.1, systemd 257):** `systemd-run --unit=mxfs-cgtest --collect python3 -c "Popen(['sh','-c','sleep 8; echo alive > /run/x'], start_new_session=True)"` → the unit deactivated at once, `/run/x` never appeared, `systemctl show -p KillMode` = control-group.

**How to apply:**
- Work that must outlive a unit's main process runs in that process (sleep, then act) or as its own unit (`systemd-run --unit=...`, a timer).
- The same detach is fine where no unit owns the caller: DRBD's handlers run from the kernel's usermode helper, outside any service cgroup, which is why the fence-peer loser's delayed restart works.
- Test a delayed action from a unit by checking that the action happened, not that it was logged.
