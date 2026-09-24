---
name: trap-stale-automatic-iscsi-node-records-add-two-minutes-to-a-rig-victims-boot
description: TRAP (0.89.84): test1/test2 kept node.startup=automatic for the SCST target (192.168.120.1/.2); with SCST down, boot waits 2 min and crash_audit over…
metadata:
  type: feedback
tags: [rig, iscsi, boot, crash_audit, trap, timeout]
---

The 0.89.84 2/tcp suite failed crash_audit at 241/300 s with every MXFS assertion of the death oracle PASSING (fence certified, replay complete 78 s after the kill, 200/200 acknowledged files verified). The oracle had no RESULT line: crash_audit's `timeout 240` killed it while it waited (tcp_death_replay.sh, after "ssh reachable") for the rebooted victim's /run/nologin to clear.

Cause, from test2 itself: `systemd-analyze blame` — open-iscsi.service 2min 2s; boot 2min 31s. The rig VMs carry node records for iqn.2026-05.local.mxfs:shared at 192.168.120.1 and .2 (the SCST/multipath rig on clyde) with node.startup=automatic; when SCST is not loaded, each boot waits for those logins to time out before remote-fs-pre.target.

Fix applied: those records set to node.startup=manual on test1/test2 (`iscsiadm -m node -T iqn.2026-05.local.mxfs:shared -o update -n node.startup -v manual`). scripts/mpath_up.sh sets them back to automatic when it brings the SCST multipath rig up, so this is reversible by design.

How to apply: when a death/reboot lap overruns with its MXFS checks passing, read the victim's `systemd-analyze blame` / `critical-chain` before suspecting MXFS. Any rig VM that boots slowly may have automatic records for a target that is down (`iscsiadm -m node` + grep node.startup /etc/iscsi/nodes/*/*/default). The Ubuntu packaged pair test3/test4's ~3 min reboot was attributed to lvm2-monitor — check it for the same cause.

Related harness faults found the same day in tests/packaged_round.sh (both fixed): peer= was given a hostname (the kernel refuses "'test4' is not a unicast IPv4 address"), and the QNAP login was left node.startup=manual so the LUN did not return after the round's reboot on Proxmox.
