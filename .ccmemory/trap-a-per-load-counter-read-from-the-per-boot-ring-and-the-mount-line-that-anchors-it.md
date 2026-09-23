---
name: trap-a-per-load-counter-read-from-the-per-boot-ring-and-the-mount-line-that-anchors-it
description: TRAP (sess582): dmesg is per BOOT and survives a module reload; MXFS probe counters and print budgets are per LOAD. Two harness FAILs came from mixin…
metadata:
  type: feedback
tags: [trap, dmesg, probe-budget, harness]
---

# A per-load counter must not be read against the per-boot ring

**What happened (sess582, tests/inact_cert_arms.sh on the 2/tcp rig).**

1. `P-INACT-CERT ino=... installed=` prints only the first 96 per module load.
   The defer arm's 1100-file filler spent that budget, and the two arms run
   afterwards on the same load asserted `installed=1 >= N` against a silenced
   probe and FAILED — while the injection arm in the same run classed a
   certificate that was demonstrably there. A budgeted probe that has gone
   quiet is neither PASS nor FAIL; it is UNREADABLE and must be reported so.
2. The census `P-INACT-CERT-TOTAL evict_ok=` was read whole-ring for "pre"
   and after a reload for "post": pre=1115 (previous load), post=8 (this
   load), delta -1107, FAIL — on a lap whose real number was exactly the 8
   inodes under test.

**Why.** `dmesg` is the kernel's ring: it is cleared by a reboot, not by a
module reload. Every MXFS probe counter and print budget is a static in the
module and resets on insmod. Nothing the module prints marks a load (the
"module verification failed" notice prints once per boot).

**The anchor.** Every mount prints `MXFS-MEMBERSHIP local=<id>
active_count=1` first, and no inode-path probe can precede a mount, so
"everything after the last such line" is this mount, hence this load:

    dmesg | tac | sed '/MXFS-MEMBERSHIP local=[0-9]* active_count=1/q' | tac

A same-load remount moves the anchor without resetting the counter, which
under-counts — toward FAIL, never toward a false PASS. Use it for any
per-load read: budgets, censuses, "pre" baselines.

Related: probe-counts-are-per-module-load-and-capped,
trap-a-cumulative-dmesg-sweep-produces-false-verdicts.
