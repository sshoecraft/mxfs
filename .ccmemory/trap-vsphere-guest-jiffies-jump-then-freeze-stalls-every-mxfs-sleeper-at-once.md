---
name: trap-vsphere-guest-jiffies-jump-then-freeze-stalls-every-mxfs-sleeper-at-once
description: TRAP (0.89.81): nested-vSphere Ubuntu guests' jiffies jump ~516 s ahead then freeze until real time catches up; every MXFS sleeper stalls at once.
metadata:
  type: feedback
tags: [vsphere, timekeeping, jiffies, rig, measurement-trap]
---

**Signature.** On the vSphere Ubuntu 24.04 guests (vstest1/vstest2, 6.8.0-53, clocksource tsc, ESXi nested in VMware Workstation on clyde), every MXFS kernel thread goes silent at once. All are in S state in their own timed sleep (`msleep_interruptible`, `cond_timedwait`, `msleep`), none is D-state or blocked on a lock, while userspace (`sleep 1`, sshd) runs normally and the guest's uptime tracks clyde's clock. What follows looks like an MXFS failure: a lone node's lease expires and it self-fences, the peer is declared dead hundreds of seconds late, and a mount sits in its survivor scan past its window.

**Cause, measured.** The guest's jiffies jumped +516,630 ticks (HZ=1000) in 1.4 s, then froze until real time caught up; it resumed at the predicted uptime to within 2 s. Timer interrupts (LOC in /proc/interrupts) kept arriving on both CPUs. Userspace sleeps are hrtimers and unaffected; kernel msleep and schedule_timeout run on jiffies and stall. VMware guests trust the TSC, so no clocksource watchdog message appears. MXFS never touches timekeeping.

**How to tell.** Before diagnosing an "every MXFS thread stopped" incident on any VM, compare `jiffies:` from /proc/timer_list against /proc/uptime: jiffies minus INITIAL_JIFFIES (4294667296 on 64-bit, HZ=1000) should equal uptime in ms. tests/vsphere_lone_mount_stall.sh samples this every second and reports the longest flat stretch in its verdict.

**Why it matters.** Three critical/high records were filed against MXFS from this before it was measured (removed in 0.89.81). A record whose "survivor" returned EIO was the survivor's own correct self-fence after its jiffies froze. Evidence: tests/evidence/vsphere_lone_mount_stall/20260923T212257.
