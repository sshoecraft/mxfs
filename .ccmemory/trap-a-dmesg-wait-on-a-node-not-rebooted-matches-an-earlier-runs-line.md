---
name: trap-a-dmesg-wait-on-a-node-not-rebooted-matches-an-earlier-runs-line
description: TRAP (0.90.106): a test waiting for 'P-SB-COVER-PARK' in dmesg matched the PREVIOUS run's line (prep reloads the module, not the VM); scope to the ru…
metadata:
  type: feedback
---

tests/rig_unmount_cover_race.sh waited for a probe line with `dmesg | grep 'P-SB-COVER-PARK slot'`. `run.sh ... prep_cluster` reloads mxfs.ko but does not reboot the rig VM, so the kernel ring still held the previous lap's line (same pid, the old message text). The wait matched at once, the test shut down and unmounted before this lap's worker had parked, and the lap read PASS having exercised nothing.

Rule of thumb: every "wait for line X" or "count line X" on a rig node or PVE host reads only what follows a mark the test wrote to /dev/kmsg itself (`awk -v m="$MARK" 'index($0,m){p=1} p'`). A matched line whose text differs from the build's current format string is the tell.

Related: trap-a-kept-row-kernel-log-starts-with-the-ring-backlog-so-count-only-after-the-rows-own-mark.
