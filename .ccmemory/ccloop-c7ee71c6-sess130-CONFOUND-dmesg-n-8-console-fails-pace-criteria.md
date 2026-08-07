---
name: ccloop-c7ee71c6-sess130-CONFOUND-dmesg-n-8-console-fails-pace-criteria
description: sess130 A/B: dmesg -n 8 in cc_grantwait/cc_bastcensus mark turned crash_consistency PASS 79s into FAIL 90/90 NO_TERMINAL_RECORD=32. Console, not FS.
metadata:
  type: project
tags: [measurement-hygiene, rule0, rule4, crash_consistency, harness, console-loglevel]
---

# `dmesg -n 8` IS A PACE-CRITERION KILLER ON THIS RIG (sess130, proven A/B)

## The trap
`tests/cc_grantwait.sh arm|mark` and `tests/cc_bastcensus.sh mark` used to run
`dmesg -n 8` on every node before stamping the kmsg boundary. That raises
**console_loglevel to 8**, so every mxfs pr_warn/pr_info is additionally pushed
to the console — synchronously, under console_lock.

Every test VM has an emulated isa-serial console backed by a **host file**:

    <serial type='pty'><log file='/var/log/libvirt/qemu/testN-serial.log'/>

`run.sh`'s `prep_cluster` deliberately sets `sysctl -w kernel.printk='1 4 1 1'`
(console level 1) on every node for exactly this reason. The mark harnesses
silently reversed it.

**`dmesg -n 8` buys NOTHING for harvesting.** printk always stores into the
kernel ring buffer; console_loglevel gates only the console, and `dmesg` reads
the ring buffer. The cost was pure loss.

## The A/B — same build 0.11.453, same virgin-fs recipe, only the console differs

| console_loglevel | crash_consistency 32/caw virgin fs | hostload |
|---|---|---|
| 8 (old mark harness) | FAIL nodes_pass=0/32, 90s/90s, NO_TERMINAL_RECORD=32 | 11.08 |
| 1 (run.sh's own) | PASS 32/32, 79s/90s, checks 204/204 | 15.72 |

The failing run was at the *lower* host load, so this is not load noise.
Direct evidence: **7061 `mxfs:` lines** written to test1's host serial log
during the loglevel-8 run.

## What this invalidates
Any measurement taken inside a `cc_grantwait.sh arm|mark` or
`cc_bastcensus.sh mark` window BEFORE sess130 was taken at console level 8.
That includes sess126's headline "ino 128 mean grant wait 3533 ms" (measured
with `arm`, which set BOTH instr=1 and console 8). The *direction* of that
finding stood up — the yield-ticket convoy was real — but its magnitudes are
inflated by console cost and must not be quoted as clean baselines.

## The fix (in tree)
`tests/quiet_console.sh` exports `$QUIET_CONSOLE`, which RE-ASSERTS
`sysctl -w kernel.printk='1 4 1 1'`. Both harnesses now source it instead of
running `dmesg -n 8`. New `tests/cc_yieldcensus.sh` does the same.

## The general rule
This is the same trap `tests/cluster_authority_merge.sh:40` already documented
for `mxfs.instr` (instr=1 turned dir_reuse_coherency PASS 32/32 109s into FAIL
0/32 111s) — but through a DIFFERENT knob, and it fires even with instr=0.
Before trusting any pace measurement, check `cat /proc/sys/kernel/printk` on
the nodes. It must read `1 4 1 1`.
