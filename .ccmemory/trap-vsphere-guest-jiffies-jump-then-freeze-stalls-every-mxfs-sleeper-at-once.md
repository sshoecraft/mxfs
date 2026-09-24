---
name: trap-vsphere-guest-jiffies-jump-then-freeze-stalls-every-mxfs-sleeper-at-once
description: TRAP (0.89.81/82): guests on an oversubscribed clyde lose kernel timers (jiffies jump+freeze, RCU stalls) — nested vSphere AND plain KVM rig VMs; eve…
metadata:
  type: feedback
tags: [vsphere, timekeeping, jiffies, rig, host-load, measurement-trap]
---

**Signature.** Every MXFS kernel thread goes silent at once. Each sits in S state in its own timed sleep (`msleep_interruptible`, `cond_timedwait`, `msleep`), none is in D state, and userspace (`sleep 1`, sshd) may keep running. What follows looks like an MXFS failure: a lone node's lease expires and it self-fences, a peer is declared dead hundreds of seconds late, and a mount overruns its survivor-scan window.

**Cause, measured twice.**
1. **Nested vSphere guests** (vstest1/2, 0.89.81): jiffies jumped +516,630 ticks in 1.4 s, then froze until real time caught up, and resumed at the predicted uptime to within 2 s. LOC timer interrupts kept arriving throughout. Evidence: tests/evidence/vsphere_lone_mount_stall/20260923T212257.
2. **Plain KVM rig guests on clyde** (test1, test2, 0.89.82) with the host at loadavg 300–400: soft lockups of 39–194 s, "rcu_preempt kthread timer wakeup didn't happen", "Possible timer handling issue on cpu=N". The guests then dropped off the network: no DNS, no ARP entry, but a login prompt on the console. The load came from the user's python jobs, the VMware nested ESXi hosts, and our own parallel builds. Read it with `sudo -n tail /var/log/libvirt/qemu/<vm>-serial.log`.

**How to tell.** Before diagnosing an "every MXFS thread stopped" or "rig VM unreachable" incident, check `cat /proc/loadavg` on clyde and the guest's serial log for RCU and soft-lockup lines. Compare `jiffies:` from /proc/timer_list with /proc/uptime: jiffies minus INITIAL_JIFFIES (4294667296 on 64-bit, HZ=1000) should equal uptime in ms. tests/vsphere_lone_mount_stall.sh samples this every second.

**Don't add load.** Never run two full kernel builds in parallel on clyde (make -j16 alongside a container make -j56 pushed it to 400). A `docker exec` build whose client dies keeps compiling inside the container. scripts/rhel_kbuild_check.sh now restarts its container first.

**Why it matters.** Three critical/high records were filed against MXFS from this before it was measured (all removed in 0.89.81). A "survivor" returning EIO was the survivor's own correct self-fence after its jiffies froze.
