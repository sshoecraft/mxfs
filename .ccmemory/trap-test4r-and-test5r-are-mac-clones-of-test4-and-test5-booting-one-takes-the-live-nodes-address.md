---
name: trap-test4r-and-test5r-are-mac-clones-of-test4-and-test5-booting-one-takes-the-live-nodes-address
description: TRAP: a recovery clone left defined with the live node's MAC takes its IP when booted (test4r did, 2026-09-24; test4r/test5r now deleted). Undefine c…
metadata:
  type: feedback
---

sess377's host-corruption recovery (docs/history/clyde-host-ext4-slab-corruption-kills-rig-nodes-sess377.md) built replacement disks test4r/test5r and left them DEFINED in qemu:///system with the originals' MACs. The live test4/test5 went back to their own images (test4 runs test4/test4.new), so the clones sat unused for five weeks; the user did not know what they were.

On 2026-09-24 scripts/vm_reclaim_disk.sh booted test4r to trim it: same MAC 52:54:00:e5:b5:82 → same static address .158 as the running test4. After test4r was destroyed, br0 kept forwarding test4's MAC to the vanished tap port ('No route to host' with ARP REACHABLE) until test4 was restarted (back at +33 s). Both clones were then deleted at the user's direction.

Lessons: a recovery clone is scratch — undefine and delete it once the original is back, or give it a new MAC before it is ever defined. A VM name with no DNS entry that shares a MAC with a live domain is a clone; never boot it while the original runs. If a node goes 'No route to host' right after a clone was up, restart the node (the bridge relearns) rather than chasing ARP.

Also from that session: rig guests test5+ still have iSCSI node records that log in at boot to the absent SCST target — boot waits ~2 min in open-iscsi.service and /run/nologin can persist for minutes; root ssh works before it clears.
