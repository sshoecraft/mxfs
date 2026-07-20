---
name: sess31-BREAKTHROUGH-duplicate-iscsi-iqn-was-the-8node-flakiness
description: sess31: ROOT of multi-session 8-node flakiness = DUPLICATE iSCSI InitiatorName on 6 nodes (QNAP target drops conflicting sessions). Fixed→4/tcp 17/17.
metadata:
  type: project
---

## sess31 BREAKTHROUGH — the "8-node flakiness / node wedge cascade" was INFRASTRUCTURE, not mxfs

### Root cause
The shared LUN is a **QNAP TS-453Pro iSCSI target at 192.168.1.4:3260** (iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772) — NOT SCST on clyde (the topology memory was stale). SIX of the 8 test VMs shipped with the SAME default Ubuntu iSCSI InitiatorName `iqn.2004-10.com.ubuntu:01:68299635f96d` (test1,4,5,6,7,8). Only test2/test3 had unique names (testN-mxfs-node). Duplicate IQNs make the QNAP target drop/conflict the colliding sessions → `connection1:0: detected conn error (1020)` flapping every ~2.5s → that node's /dev/sda I/O fails → mxfs sees EIO → readdir=0 (whole FS view gone) → the running coordinated test fails 0/N, then EVERY subsequent test sees the wedged node as 3/4 = CASCADE.

### Why this hid for ~30 sessions
- **2/tcp passed 17/17** because only test1+test2 run; test2's IQN is unique and test1 is the sole user of the dup name → no collision.
- **4/tcp / 8/tcp failed** because test4 (and at 8: test4-8) collide with test1 on the dup IQN. The wedged node looked exactly like an mxfs coherency bug: dir_reuse "node4 readdir=0, peers miss node4's 100 entries", crash_consistency "durable empty .md5 sidecars" — all really EIO from the flapping iSCSI session.

### Diagnosis signature (how to spot it again)
`dmesg | grep -c 'conn error'` — a healthy node = 0; a colliding node = 100s and STILL counting (last ts ≈ current uptime). `iscsiadm -m session` shows the QNAP portal. `cat /etc/iscsi/initiatorname.iscsi` — compare across nodes; ANY duplicate = bug.

### Fix (applied sess31)
Set unique `InitiatorName=iqn.2004-10.com.ubuntu:01:test<N>-mxfs-node` in /etc/iscsi/initiatorname.iscsi on test4,5,6,7,8 (test1 keeps the old name, now unique). Persisted on each VM's root disk → survives the virsh destroy/start reboots. The QNAP has no restrictive ACL (accepts custom IQNs — test2/test3 prove it). Verified: test4 post-reboot conn_errors=0, /dev/sda 217 MB/s.

### Result
**full 4/tcp = 17/17** (was 13/17 with cascade) after the fix + a node-disk cleanup (see [[sess31-node-disk-fill-from-kernlog-flood]]). 1/tcp=16/16, 2/tcp=17/17. 8/tcp testing next.

### Also fixed this session
Node root disks were 100% full (test1/test4) from ~20GB /var/log/{syslog,kern.log} (always-on mxfs probe flood via rsyslog, cumulative over 30 sessions). This ENOSPC broke dkms_install (1/tcp). Truncated logs → 1/tcp 16/16. The flood will refill over many runs — consider gating the always-on printk or auto-truncating in run.sh prep.
</body>
