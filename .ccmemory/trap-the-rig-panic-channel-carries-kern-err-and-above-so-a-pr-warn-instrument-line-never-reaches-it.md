---
name: trap-the-rig-panic-channel-carries-kern-err-and-above-so-a-pr-warn-instrument-line-never-reaches-it
description: TRAP (0.90.29, re-measured 0.90.37): rig guests' console loglevel is 1: only KERN_EMERG and panics reach netconsole; pr_err probes land in dmesg only.
metadata:
  type: feedback
tags: [netconsole, instrument, rig, loglevel]
---

# The rig's panic channel carries panics, not errors or warnings

**What happened (0.90.29).** An instrument printed at module unload with `pr_warn`, so that "the line reaches the console before the panic it explains". Ten such lines were in the nodes' journals, and `tests/evidence/netconsole.log` held none. At the time this was read as "the console passes KERN_ERR and above".

**Re-measured (0.90.37, 2026-09-30).** A KERN_ERR (`pr_err`) probe fired about 1,000 times across test1-14 and showed up in each node's `dmesg`. `netconsole.log` received 0 of those lines. On test3, `/proc/sys/kernel/printk` reads `1 4 1 1`: the console loglevel is 1, so only KERN_EMERG goes to the consoles, netconsole included. A panic still arrives, because panic and oops raise the console level. The only other lines the listener received after its restart were boot-time lines, sent before the level was lowered.

**What to do:**
- Treat the channel as panic-only. Collect a probe from each node's `dmesg` or journal as soon as the lap ends, and do it before the journal rotates it out (a separate trap covers journals rotating quickly under load).
- If an instrument line has to survive a guest panic, print it at the moment of the panic. Alternatively, raise the console level on the nodes for that investigation only, and restore it afterwards.
- Before relying on the channel for a line, check that one known occurrence of it is in `tests/evidence/netconsole.log`.
- A count of 0 in the channel for any non-panic tag is a capture limit. It is never evidence that the line was absent.
