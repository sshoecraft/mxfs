---
name: trap-a-node-in-two-verification-sets-orders-its-luns-by-session-so-a-device-path-can-name-the-other-set-lun
description: TRAP (0.90.11): test3 was in the rig AND the ubuntu2404 pair; after a power cycle its platform LUN was /dev/sda, prep mounted it there, cluster never…
metadata:
  type: feedback
tags: [rig, iscsi, prep, identity, platform]
---

# A node in two verification sets orders its LUNs by iSCSI session

**What happened (2026-09-28, 4/tcp prep, session s4).** test3 and test4 were rig
nodes (test1-4) AND the ubuntu2404 platform pair, so each logged into two SCST
targets at boot (`:shared` and `:plat-ubuntu2404`). After a prep escalation
power-cycled test3, its sessions came up in the other order: the 64 GB platform
LUN was `/dev/sda` and the 128 GB rig LUN `/dev/sdb` (test4 had them the other
way round). `run.sh` passed `MXFS_DEV=/dev/sda` to every node's prep_node.sh,
test3 mounted the platform LUN alone, and the only symptom was
`PREP FAIL: cluster did NOT converge to 4 members within 110s` with test3 at
`active_count=1` while the other three formed a view. Bridge multicast was
suspected first and was innocent (`bridge mdb` empty, `mcast_flood on`).

**The instrument that settled it:** `/sys/block/sd*/device/wwid` on each node
(rig LUN `eui.3265343736643037`, platform LUN `eui.346161386665642d`).

**Fixes in the tree (0.90.11):**
- `run.sh` reads the freshly formatted LUN's identity from node 1
  (`tests/setup/dev_identity.sh`: fsid + wwid) and ships `MXFS_FSID` /
  `MXFS_LUN_WWID` to every `prep_node.sh`, which rebinds `MXFS_DEV` to the
  block device carrying that identity (`DEVICE-REBOUND:` line) or refuses.
- `scripts/scst_platform_targets.sh setup` now REMOVES initiators that left a
  platform's set from its ini_group (it only ever added them before).
- The ubuntu2404 set moved to test5-8 (`nodes ubuntu2404=test5,test6,test7,test8`);
  rig nodes must never be in a platform set.

**Rule of thumb:** a device path is a locator, not an identity; any harness
that hands a path to more than one node must bind by wwid/fsid on each node.
